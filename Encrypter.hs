import Data.Bits
import Data.Word

data Word128 = Word128 [Word32]

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

-- Inverse Rijndael S-box
invSbox :: Word8 -> Word8
invSbox b = gfInv $ (rotateL b 1) `xor` (rotateL b 3) `xor` (rotateL b 6) `xor` 0x5

-- Map function on a 8-bit words to each byte of the argument
mapBytes_32 :: (Word8 -> Word8) -> Word32 -> Word32
mapBytes_32 f x = go f x 0 0
    where
        go :: (Word8 -> Word8) -> Word32 -> Int -> Word32 -> Word32
        go f x i acc | i == 4 = acc
                     | otherwise = go f x (i+1)  $ xor acc $ shiftR ((fromIntegral 
                        (f ((fromIntegral (shiftL x (8*i))) :: Word8))) :: Word32) (8*i)

--Lookup table for round constants
aes_rc :: [Word32]
aes_rc = [0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 
    0x00000040, 0x00000080, 0x0000001B, 0x00000036]

-- Generate expanded key for AES-128
keySchedule :: Word128 -> [Word128]
keySchedule key = go 0 key
    where
        go :: Int -> Word128 -> [Word128]
        go n prev@(Word128 prevLs) | n < 10 = curr : (go (n+1) curr)
                                   | otherwise = []
                    where curr = Word128 $ buildKeyWords 0 n prev (prevLs !! 3)
        buildKeyWords :: Int -> Int -> Word128 -> Word32 -> [Word32]
        buildKeyWords i keyIndex prevKey@(Word128 prevKeyLs) prevWord | i == 4 = []
                                                | otherwise = currWord : (buildKeyWords (i+1) keyIndex prevKey currWord)
            where prevKeyWord = prevKeyLs !! i
                  currWord | i == 0 = prevKeyWord `xor` (aes_rc !! keyIndex) `xor` (mapBytes_32 sbox (rotateL prevWord 8))
                           | otherwise = prevKeyWord `xor` prevWord

{- 
-- Construct Word128 from list of Word32
construct128 :: [Word32] -> Word128
construct128 = go 0
    where
        go _ [] = 0
        go i (x:xs) = (shiftR ((fromIntegral x) :: Word128) (i*32)) `xor` (go (i+1) xs)
-}