module Encrypter (
    Vec,
    Word128,
    mkVec,
    mapM_Vec,
    zipVec,
    zipVecWith,
    indexVec,
    replicateVec,
    encryptBlock,
    decryptBlock,
    keySchedule
) where

{-# LANGUAGE DataKinds, ScopedTypeVariables, GADTs #-}

import Data.Bits
import Data.Word
import Data.Array
import Data.Finite
import Data.Proxy
import qualified Data.Vector as V
import GHC.TypeNats

-- Declare fixed size data type and operations

data Vec (n :: Nat) a = UnsafeMkVec { getVector :: V.Vector a }
    deriving Show

type Word128 = Vec 4 Word32

mkVec :: forall n a. KnownNat n => V.Vector a -> Vec n a
mkVec v | V.length v == l = UnsafeMkVec v
        | otherwise       = error "Vector of incorrect size."
  where
    l = fromIntegral (natVal (Proxy @n))

mapVec :: (a -> b) -> Vec n a -> Vec n b
mapVec f v = UnsafeMkVec $ V.map f (getVector v)

instance Functor (Vec n) where
    fmap = mapVec

mapM_Vec :: Monad m => (a -> m b) -> Vec n a -> m ()
mapM_Vec f v = V.mapM_ f (getVector v)

zipVec :: Vec n a -> Vec n b -> Vec n (a, b)
zipVec (UnsafeMkVec xs) (UnsafeMkVec ys) = UnsafeMkVec (V.zip xs ys)

zipVecWith :: (a -> b -> c) -> Vec n a -> Vec n b -> Vec n c
zipVecWith f (UnsafeMkVec xs) (UnsafeMkVec ys) = UnsafeMkVec (V.zipWith f xs ys)

indexVec :: Vec n a -> Finite n -> a
indexVec v i = getVector v V.! fromIntegral (getFinite i)

replicateVec :: forall n a. KnownNat n => a -> Vec n a
replicateVec x = UnsafeMkVec $ V.replicate l x
  where
    l = fromIntegral (natVal (Proxy @n))

-- Begin main code

bitlength :: Word16 -> Int
bitlength = go (-1)
    where
        go :: Int -> Word16 -> Int 
        go size b | b == 0 = size
                  | otherwise = go (size + 1) $ shiftR b 1

gfInv :: Word8 -> Word8
gfInv b = (fromIntegral (go 0x11b ((fromIntegral b) :: Word16) 0 1)) :: Word8
    where
        go :: Word16 -> Word16 -> Word16 -> Word16 -> Word16
        go r newR t newT = 
          if(newR /= 0)
            then let q = ((bitlength r) - (bitlength newR))
                in if (q >= 0)
                    then go newR (xor r (shiftL newR q)) newT (xor t (shiftL newT q))
                    else go newR r newT t
            else if t >= 0x100 then (t `xor` 0x11b) else t

convolute :: Word16 -> Word16 -> Word16
convolute = go 0
    where
        go :: Word16 -> Word16 -> Word16 -> Word16
        go acc x y | x /= 0 = 
                        let xnew = shiftR x 1
                            ynew = shiftL y 1
                        in if (x .&. 1) == 1
                            then go (acc `xor` y) xnew ynew
                            else go acc xnew ynew
                   | otherwise = acc

-- Perform multipilcation on GF[2^8]/(x^8+x^4+x^3+x+1)
gfMult :: Word8 -> Word8 -> Word8
gfMult x y = (fromIntegral (gfRemainder (convolute ((fromIntegral x) :: Word16) ((fromIntegral y) :: Word16)) 0x11b)) :: Word8

deconvolute :: Word16 -> Word16 -> (Word16, Word16)
deconvolute x y = go x 0 y
    where
        go :: Word16 -> Word16 -> Word16 -> (Word16, Word16)
        go r q y =
            let yLen = (bitlength y)
                index = ((bitlength r) - yLen)
            in if index >= 0
                  then go (xor r (shiftL y index)) (xor q (shiftL 1 index)) y
                  else (q, r)

gfDiv :: Word16 -> Word16 -> Word16
gfDiv x y = fst $ deconvolute x y

gfRemainder :: Word16 -> Word16 -> Word16
gfRemainder x y = snd $ deconvolute x y

-- Computes Rijndael S-box of an 8-bit word
sbox :: Word8 -> Word8
sbox b = bInv `xor` (rotateL bInv 1) `xor` (rotateL bInv 2)
    `xor` (rotateL bInv 3) `xor` (rotateL bInv 4) `xor` 0x63
    where bInv = gfInv b

-- S-box lookup table
sboxTable :: Array Word8 Word8
sboxTable = array (0,255) $ zip is $ map sbox is
    where is :: [Word8]
          is = [0..255]

-- Inverse Rijndael S-box
invSbox :: Word8 -> Word8
invSbox b = gfInv $ (rotateL b 1) `xor` (rotateL b 3) `xor` (rotateL b 6) `xor` 0x5

-- Inverse S-box lookup table
invSboxTable :: Array Word8 Word8
invSboxTable = array (0,255) $ zip is $ map invSbox is
    where is :: [Word8]
          is = [0..255]

-- Map function on 8-bit words to each byte of the 32-bit argument
mapBytes_32 :: (Word8 -> Word8) -> Word32 -> Word32
mapBytes_32 f x = go f x 0 0
    where
        go :: (Word8 -> Word8) -> Word32 -> Int -> Word32 -> Word32
        go f x i acc | i == 4 = acc
                     | otherwise = go f x (i+1)  $ xor acc $ shiftL ((fromIntegral 
                        (f ((fromIntegral (shiftR x (8*i))) :: Word8))) :: Word32) (8*i)

-- Map function on 8-bit words to each byte of the 128-bit argument
mapBytes_128 :: (Word8 -> Word8) -> Word128 -> Word128
mapBytes_128 bf x = fmap (mapBytes_32 bf) x

--Lookup table for round constants
aes_rc :: V.Vector Word32
aes_rc = V.fromList [0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 
    0x00000040, 0x00000080, 0x0000001B, 0x00000036]

-- Generate expanded key for AES-128
keySchedule :: Word128 -> [Word128]
keySchedule key = go 0 key
    where
        go :: Int -> Word128 -> [Word128]
        go n prev | n < 10 = prev : go (n+1) curr
                  | otherwise = [prev]
                    where curr = (mkVec $ V.fromList $ buildKeyWords 0 n prev $ indexVec prev 3) :: Word128
        buildKeyWords i keyIndex prevKey prevWord | i == 4 = []
                                                  | otherwise = currWord : (buildKeyWords (i+1) keyIndex prevKey currWord)
            where prevKeyWord = indexVec prevKey (finite i :: Finite 4)
                  currWord | i == 0 = prevKeyWord `xor` (aes_rc V.! keyIndex) `xor` (mapBytes_32 (sboxTable !) (rotateL prevWord 8))
                           | otherwise = prevKeyWord `xor` prevWord

encryptBlock :: Array Int Word128 -> Word128 -> Word128
encryptBlock keySch state = addRoundKey 10 $ shiftRows $ subBytes $ go 1 $ addRoundKey 0 state
    where subBytes state = mapBytes_128 (sboxTable !) state
          shiftRows state = zipVecWith rotateL state $ (mkVec (V.enumFromStepN 0 8 4)) :: Word128
          addRoundKey i state = zipVecWith xor (keySch ! i) state
          go i state | i < 10 = go (i+1) $ addRoundKey i $ mixColumns $ shiftRows $ subBytes state
                     | otherwise = state

mixColumns :: Word128 -> Word128       
mixColumns state = go 0 state $ replicateVec 0 :: Word128
    where 
        go i state accState
            | i < 4 = go (i+1) state $ zipVecWith xor accState $ (mkVec putBytes) :: Word128
            | otherwise = accState
            where
                extractedBytes = V.map (\x -> (fromIntegral (shiftR x (8*i))) :: Word8) $ getVector state
                transformedBytes = bitMVMult mixColArray extractedBytes
                putBytes = V.map (\x -> (shiftL ((fromIntegral x) :: Word32) (8*i))) transformedBytes

mixColArray :: Array (Int, Int) Word8
mixColArray = array ((0,0),(3,3)) $ [if i==j then ((i,j), 2)
                                        else if ((i+1) == j) || (i== 3 && j==0) then ((i,j), 3)
                                            else ((i,j), 1) | i <- range (0,3), j <- range (0,3)]

decryptBlock :: Array Int Word128 -> Word128 -> Word128
decryptBlock keySch state = addRoundKey 0 $ go 9 $ invSubBytes $ invShiftRows $ addRoundKey 10 state
    where invSubBytes state = mapBytes_128 (invSboxTable !) state
          invShiftRows state = zipVecWith rotateR state $ (mkVec (V.enumFromStepN 0 8 4)) :: Word128
          addRoundKey i state = zipVecWith xor (keySch ! i) state
          go i state | i > 0 = go (i-1) $ invSubBytes $ invShiftRows $ invMixColumns $ addRoundKey i state
                     | otherwise = state                                    

invMixColumns :: Word128 -> Word128       
invMixColumns state = go 0 state $ replicateVec 0 :: Word128
    where 
        go i state accState
            | i < 4 = go (i+1) state $ zipVecWith xor accState $ (mkVec putBytes) :: Word128
            | otherwise = accState
            where
                extractedBytes = V.map (\x -> (fromIntegral (shiftR x (8*i))) :: Word8) $ getVector state
                transformedBytes = bitMVMult invMixColArray extractedBytes
                putBytes = V.map (\x -> (shiftL ((fromIntegral x) :: Word32) (8*i))) transformedBytes

invMixColArray :: Array (Int, Int) Word8
invMixColArray = array ((0,0),(3,3)) $ [if i==j then ((i,j), 14)
                                         else if ((i+1) == j) || (i== 3 && j==0) then ((i,j), 11)  
                                           else if (i == (j+1)) || (i == 0 && j==3) then ((i,j), 9)
                                            else ((i,j), 13) | i <- range (0,3), j <- range (0,3)]

-- Bitwise matrix-vector multiplication as used in the AES mixColums step. Uses xor as addition
-- and multipilcation on GF[2^8]/(x^8+x^4+x^3+x+1).
bitMVMult :: Array (Int, Int) Word8 -> V.Vector Word8 -> V.Vector Word8
bitMVMult a x
    -- Ensure correct dimensions for multiplication
    | (uj-lj+1) /= len = error "Incorrect dimensions for matrix-vector multiplication."
    | otherwise = V.fromList [foldl xor 0 [gfMult (a!(i,j)) (x V.! (j-lj)) | j <- range (lj,uj)] | i <- range (li,ui)]
      where ((li,lj),(ui,uj)) = bounds a
            len = length x
