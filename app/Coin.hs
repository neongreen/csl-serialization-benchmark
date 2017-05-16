module Coin (encodeCoin, decodeCoin, decodeVarint, hdrToParam) where

import Universum

import Data.Bits

import Types (Coin(..))

encodeCoin :: Coin -> [Word8]
encodeCoin (Coin w) = encodeVarint mega ++ encodeVarint (reversedBase10 micros)
  where
    (mega, micros) = w `divMod` 1000000

encodeVarint :: Word64 -> [Word8]
encodeVarint w
    | w <= 0x7F         = [fromIntegral w]
    | w <= 0x3FFF       = [0x80 .|. (w .>>. 8), fromIntegral w]
    | w <= 0x1FFFFF     = [0xc0 .|. (w .>>. 16), w .>>. 8, fromIntegral w]
    | w <= 0x0FFFFFFF   = [0xe0 .|. (w .>>. 24), w .>>. 16, w .>>. 8, fromIntegral w]
    | w <= 0x0FFFFFFFFF = [0xf0 .|. (w .>>. 32), w .>>. 24, w .>>. 16, w .>>. 8, fromIntegral w]
    | otherwise         = error $ "invalid encoding for integral part: " <> show w

expectedContBytes :: Word64 -> Int
expectedContBytes w
    | w <= 0x7F         = 0
    | w <= 0x3FFF       = 1
    | w <= 0x1FFFFF     = 2
    | w <= 0x0FFFFFFF   = 3
    | w <= 0x0FFFFFFFFF = 4
    | otherwise         = error "invalid encoding"

hdrToParam :: Word8 -> (Int, Word64)
hdrToParam h
    | isClear h 7 = (0, fromIntegral (h .&. 0x7f))
    | isClear h 6 = (1, fromIntegral (h .&. 0x3f))
    | isClear h 5 = (2, fromIntegral (h .&. 0x1f))
    | isClear h 4 = (3, fromIntegral (h .&. 0x0f))
    | otherwise   = (4, fromIntegral (h .&. 0x0f))

(.>>.) :: Word64 -> Int -> Word8
(.>>.) w n = fromIntegral (w `shiftR` n)

isClear :: Word8 -> Int -> Bool
isClear w bitN = not (testBit w bitN)

toBase10 :: (Integral n, Ord n, Num n) => Int -> n -> [n]
toBase10 nbDigits = loop nbDigits
  where
    loop 0 _ = []
    loop i n = r : loop (i-1) b
       where (b, r) = n `divMod` 10

fromBase10 :: Num n => [n] -> n
fromBase10 = go 0
  where go !acc []     = acc
        go !acc (x:xs) = go (acc * 10 + x) xs

reversedBase10 :: (Integral n, Ord n, Num n) => n -> n
reversedBase10 = fromBase10 . toBase10 6

decodeVarint :: Word64 -> [Word8] -> Either String Word64
decodeVarint acc conts =
    let val = orAndShift acc conts in
    if expectedContBytes val == length conts
        then Right val
        else Left "not canonical encoding"
  where
    orAndShift acc []     = acc
    orAndShift acc (x:xs) = orAndShift ((acc `shiftL` 8) .|. fromIntegral x) xs

decodeCoin :: Word64 -> Word64 -> Either String Coin
decodeCoin mega microsReversed = 
    let micros = reversedBase10 microsReversed
        w      = mega * 1000000 + micros in
    if micros < 1000000 && w <= getCoin maxBound
        then Right (Coin w)
        else Left "coins above limit"
