{-# LANGUAGE DataKinds, ScopedTypeVariables, GADTs #-}

import Data.Bits
import Data.Binary.Get
import Data.Binary.Put
import Control.Monad
import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as B
import System.IO
import GHC.TypeNats
import Data.Finite
import Data.Proxy
import Data.Word
import Encrypter
import GHC.ByteOrder
import Data.Array

-- #TODO: Reuse keyschedule

-- Takes an ecrypted file specified by a filepath and exports a decrypted file
decryptFile :: FilePath -> FilePath -> Word128 -> IO ()
decryptFile pathIn pathOut key = do
    hIn <- openFile pathIn ReadMode
    hOut <- openFile pathOut WriteMode
    go hIn hOut
    hClose hIn
    hClose hOut
    where
      keySch = array (0,10) $ zip [0..10] $ keySchedule key
      go hIn hOut = do
        empty <- hIsEOF hIn
        if empty
            then pure ()
            else do
                decryptProcessBlock hIn hOut keySch
                go hIn hOut

-- Reads a word128 block from file and exports decrypted block to a given file.
decryptProcessBlock :: Handle -> Handle -> Array Int Word128 -> IO ()
decryptProcessBlock hIn hOut keySch = do
    -- Read 16 byte block 
    bs <- B.hGet hIn 16
    let block = mkVec (runGet (V.replicateM 4 safeGetWord32host) bs) :: Word128
    let decryptedBlock = decryptBlock keySch block
    let bsOut = runPut $ mapM_Vec safePutWord32host decryptedBlock
    B.hPut hOut bsOut

-- Takes an ecrypted file specified by a filepath and exports a encrypted file
encryptFile :: FilePath -> FilePath -> Word128 -> IO ()
encryptFile pathIn pathOut key = do
    hIn <- openFile pathIn ReadMode
    hOut <- openFile pathOut WriteMode
    go hIn hOut
    hClose hIn
    hClose hOut
    where
      keySch = array (0,10) $ zip [0..10] $ keySchedule key
      go hIn hOut = do
        empty <- hIsEOF hIn
        if empty
            then pure ()
            else do
                encryptProcessBlock hIn hOut keySch
                go hIn hOut

-- Reads a word128 block from file and exports encrypted block to a given file.
encryptProcessBlock :: Handle -> Handle -> Array Int Word128 -> IO ()
encryptProcessBlock hIn hOut keySch = do
    -- Read 16 byte block 
    bs <- B.hGet hIn 16
    let block = mkVec (runGet (V.replicateM 4 safeGetWord32host) bs) :: Word128
    let decryptedBlock = encryptBlock keySch block
    let bsOut = runPut $ mapM_Vec putWord32host decryptedBlock
    B.hPut hOut bsOut

-- Read a Word32 in little endian format.
-- Fills remaining bytes with zeros if end of file reached early.
safeGetWord32le :: Get Word32
safeGetWord32le = go 0 $ pure 0
    where
      go :: Int -> Get Word32 -> Get Word32
      go i acc
        | i == 4 = acc
        | otherwise = do
            empty <- isEmpty
            if empty
                then acc
                else do
                    word <- getWord8
                    let myWord32 = fromIntegral word :: Word32
                    accVal <- acc
                    go (i+1) $ pure $ xor accVal $ shiftL myWord32 (i*8)

-- Read a Word32 in big endian format.
-- Fills remaining bytes with zeros if end of file reached early.
safeGetWord32be :: Get Word32
safeGetWord32be = go 0 $ pure 0
    where
      go :: Int -> Get Word32 -> Get Word32
      go i acc
        | i == 4 = acc
        | otherwise = do
            empty <- isEmpty
            if empty
                then acc
                else do
                    word <- getWord8
                    let myWord32 = fromIntegral word :: Word32
                    accVal <- acc
                    go (i+1) $ pure $ xor accVal $ shiftL myWord32 ((3-i)*8)

-- Read a Word32 in host endianness format.
-- Fills remaining bytes with zeros if end of file reached early.
safeGetWord32host :: Get Word32
safeGetWord32host = case targetByteOrder of
    BigEndian -> safeGetWord32be
    otherwise -> safeGetWord32le

-- Put bytes from Word32 in little endian format.
-- If a null byte is encountered, then stops putting bytes.
safePutWord32le :: Word32 -> Put
safePutWord32le w = go 0 w
    where
        go :: Int -> Word32 -> Put
        go i w
          | i == 4 = pure ()
          | otherwise = do
            let myWord8 = fromIntegral (shiftR w (i*8)) :: Word8
            if myWord8 == 0
                then pure ()
                else do
                    putWord8 myWord8
                    go (i+1) w

-- Put bytes from Word32 in big endian format.
-- If a null byte is encountered, then stops putting bytes.
safePutWord32be :: Word32 -> Put
safePutWord32be w = go 0 w
    where
        go :: Int -> Word32 -> Put
        go i w
          | i == 4 = pure ()
          | otherwise = do
            let myWord8 = fromIntegral (shiftR w (i*8)) :: Word8
            if myWord8 == 0
                then do go (i+1) w
                else do
                    putWord8 myWord8
                    go (i+1) w

-- Put bytes from Word32 using host's endian format.
-- If a null byte is encountered, then stops putting bytes.
safePutWord32host :: Word32 -> Put
safePutWord32host w = case targetByteOrder of
    BigEndian -> safePutWord32be w
    otherwise -> safePutWord32le w
