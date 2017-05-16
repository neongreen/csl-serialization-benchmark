{-# LANGUAGE CPP, ScopedTypeVariables #-}

module Cbor where

import Universum

import qualified Control.Monad as Monad
import qualified Data.ByteString as BS
import qualified Data.ByteArray as ByteArray
import qualified Cardano.Crypto.Wallet as CC
import Crypto.Hash
import Data.Bits

import qualified Data.Binary.Serialise.CBOR as C
import Data.Binary.Serialise.CBOR as C hiding (decode, encode)
import Data.Binary.Serialise.CBOR.Encoding as C hiding (Tokens(..))
import Data.Binary.Serialise.CBOR.Decoding as C hiding (DecodeAction(Done, Fail))
import Data.Binary.Serialise.CBOR.Write as C
import Data.Binary.Serialise.CBOR.Pretty as C

import Types
import Coin (decodeVarint, decodeCoin, hdrToParam, encodeCoin)

----------------------------------------------------------------------------
-- Utils
----------------------------------------------------------------------------

encodeCtr0 n     = encodeListLen 1 <> C.encode (n :: Int)
encodeCtr1 n a   = encodeListLen 2 <> C.encode (n :: Int) <> C.encode a
encodeCtr2 n a b = encodeListLen 3 <> C.encode (n :: Int) <> C.encode a <> C.encode b
encodeCtr3 n a b c
                 = encodeListLen 4 <> C.encode (n :: Int) <> C.encode a <> C.encode b
                      <> C.encode c
encodeCtr4 n a b c d
                 = encodeListLen 5 <> C.encode (n :: Int) <> C.encode a <> C.encode b
                      <> C.encode c <> C.encode d
encodeCtr6 n a b c d e f
                 = encodeListLen 7 <> C.encode (n :: Int) <> C.encode a <> C.encode b
                      <> C.encode c <> C.encode d <> C.encode e <> C.encode f
encodeCtr7 n a b c d e f g
                 = encodeListLen 8 <> C.encode (n :: Int) <> C.encode a <> C.encode b
                      <> C.encode c <> C.encode d <> C.encode e <> C.encode f
                      <> C.encode g

{-# INLINE encodeCtr0 #-}
{-# INLINE encodeCtr1 #-}
{-# INLINE encodeCtr2 #-}
{-# INLINE encodeCtr3 #-}
{-# INLINE encodeCtr4 #-}
{-# INLINE encodeCtr6 #-}
{-# INLINE encodeCtr7 #-}

{-# INLINE decodeCtrTag #-}
{-# INLINE decodeCtrBody0 #-}
{-# INLINE decodeCtrBody1 #-}
{-# INLINE decodeCtrBody2 #-}

decodeCtrTag = (\len tag -> (tag, len)) <$> decodeListLen <*> decodeInt

decodeCtrBody0 1 f = pure f
decodeCtrBody0 x _ = error $ "decodeCtrBody0: impossible tag " <> show x
decodeCtrBody1 2 f = do x1 <- C.decode
                        return $! f x1
decodeCtrBody1 x _ = error $ "decodeCtrBody1: impossible tag " <> show x
decodeCtrBody2 3 f = do x1 <- C.decode
                        x2 <- C.decode
                        return $! f x1 x2
decodeCtrBody2 x _ = error $ "decodeCtrBody2: impossible tag " <> show x

{-# INLINE decodeSingleCtr1 #-}
{-# INLINE decodeSingleCtr2 #-}
{-# INLINE decodeSingleCtr3 #-}
{-# INLINE decodeSingleCtr4 #-}
{-# INLINE decodeSingleCtr6 #-}
{-# INLINE decodeSingleCtr7 #-}

decodeSingleCtr1 v f = decodeListLenOf 2 *> decodeWordOf v *> pure f <*> C.decode
decodeSingleCtr2 v f = decodeListLenOf 3 *> decodeWordOf v *> pure f <*> C.decode <*> C.decode
decodeSingleCtr3 v f = decodeListLenOf 4 *> decodeWordOf v *> pure f <*> C.decode <*> C.decode <*> C.decode
decodeSingleCtr4 v f = decodeListLenOf 5 *> decodeWordOf v *> pure f <*> C.decode <*> C.decode <*> C.decode <*> C.decode
decodeSingleCtr6 v f = decodeListLenOf 7 *> decodeWordOf v *> pure f <*> C.decode <*> C.decode <*> C.decode <*> C.decode <*> C.decode <*> C.decode
decodeSingleCtr7 v f = decodeListLenOf 8 *> decodeWordOf v *> pure f <*> C.decode <*> C.decode <*> C.decode <*> C.decode <*> C.decode <*> C.decode <*> C.decode

----------------------------------------------------------------------------
-- Instances
----------------------------------------------------------------------------

#define CBOR(TYPE, CONS, FUNENC, FUNDEC, ARGS) \
    Serialise (TYPE) where \
        encode (CONS ARGS) = FUNENC 1 ARGS; \
        decode = FUNDEC 1 CONS; \
        {-# INLINE encode #-}; \
        {-# INLINE decode #-}; \

#define CBOR1(TYPE, CONS) \
    CBOR(TYPE, CONS, encodeCtr1, decodeSingleCtr1, a)
#define CBOR2(TYPE, CONS) \
    CBOR(TYPE, CONS, encodeCtr2, decodeSingleCtr2, a b)
#define CBOR3(TYPE, CONS) \
    CBOR(TYPE, CONS, encodeCtr3, decodeSingleCtr3, a b c)
#define CBOR4(TYPE, CONS) \
    CBOR(TYPE, CONS, encodeCtr4, decodeSingleCtr4, a b c d)

instance CBOR2(Block, Block)
instance CBOR3(TxPayload, UnsafeTxPayload)
instance CBOR4(VssCertificate, VssCertificate)
instance CBOR3(Commitment, Commitment)
instance CBOR3(Tx, UnsafeTx)
instance CBOR2(TxIn, TxIn)
instance CBOR2(TxOut, TxOut)
instance Serialise h => CBOR2(Attributes h, Attributes)
instance CBOR2(Script, Script)
instance CBOR2(GtPayload, CommitmentsPayload)
instance CBOR1(AddrPkAttrs, AddrPkAttrs)

mkLeafCbor :: Serialise a => a -> MerkleNode a
mkLeafCbor a =
    MerkleLeaf
    { mVal  = a
    , mRoot = hash (one 0 <> C.toStrictByteString (C.encode a))
    }
{-# INLINE mkLeafCbor #-}

mkBranchCbor :: MerkleNode a -> MerkleNode a -> MerkleNode a
mkBranchCbor a b =
    MerkleBranch
    { mLeft  = a
    , mRight = b
    , mRoot  = hash $ mconcat [ one 1 :: ByteString
                              , ByteArray.convert (mRoot a)
                              , ByteArray.convert (mRoot b) ]
    }
{-# INLINE mkBranchCbor #-}

mkMerkleTreeCbor :: Serialise a => [a] -> MerkleTree a
mkMerkleTreeCbor [] = MerkleEmpty
mkMerkleTreeCbor ls = MerkleTree (fromIntegral lsLen) (go lsLen ls)
  where
    lsLen = length ls
    go _  [x] = mkLeafCbor x
    go len xs = mkBranchCbor (go i l) (go (len - i) r)
      where
        i = powerOfTwo len
        (l, r) = splitAt i xs

instance Serialise (MerkleTree Tx) where
    encode = C.encode . toList
    decode = mkMerkleTreeCbor <$> C.decode
    {-# INLINE encode #-}
    {-# INLINE decode #-}

instance Serialise Hash where
    encode digest =
        let bs = ByteArray.convert digest :: ByteString
        in C.encode bs
    decode = do
        sbs :: ByteString <- C.decode
        case digestFromByteString sbs of
            Nothing -> error "decode@Hash: impossible"
            Just x  -> pure x
    {-# INLINE encode #-}
    {-# INLINE decode #-}

instance Serialise CC.XPub where
    encode (CC.unXPub -> kc) = C.encode kc
    decode = either Monad.fail pure . CC.xpub =<< C.decode
    {-# INLINE encode #-}
    {-# INLINE decode #-}

instance Serialise CC.XSignature where
    encode (CC.unXSignature -> kc) = C.encode kc
    decode = either Monad.fail pure . CC.xsignature =<< C.decode
    {-# INLINE encode #-}
    {-# INLINE decode #-}

instance Serialise Coin where
    encode = C.encode . BS.pack . encodeCoin
    decode = do
        x <- C.decode
        let (nbBytes1, acc1) = hdrToParam (BS.head x)
            conts1 = BS.unpack (BS.take nbBytes1 (BS.drop 1 x))
            (nbBytes2, acc2) = hdrToParam (BS.index x (nbBytes1 + 1))
            conts2 = BS.unpack (BS.drop (2 + nbBytes1) x)
        --
        either Monad.fail pure $ do
            a <- decodeVarint acc1 conts1
            b <- decodeVarint acc2 conts2
            decodeCoin a b
    {-# INLINE encode #-}
    {-# INLINE decode #-}

instance Serialise TxInWitness where
    encode = \case
        PkWitness a b -> encodeCtr2 0 a b
        ScriptWitness a b -> encodeCtr2 1 a b
        UnknownWitnessType n a -> error "crap"
    decode = decodeCtrTag >>= \case
        (0, l) -> decodeCtrBody2 l PkWitness
        (1, l) -> decodeCtrBody2 l ScriptWitness
        (n, l) -> error "crap"
    {-# INLINE encode #-}
    {-# INLINE decode #-}

instance Serialise Address where
    encode = \case
        PubKeyAddress a b -> encodeCtr2 0 a b
        ScriptAddress a -> encodeCtr1 1 a
        UnknownAddressType n a -> error "crap"
    decode = decodeCtrTag >>= \case
        (0, l) -> decodeCtrBody2 l PubKeyAddress
        (1, l) -> decodeCtrBody1 l ScriptAddress
        (n, l) -> error "crap"
    {-# INLINE encode #-}
    {-# INLINE decode #-}

powerOfTwo :: (Bits a, Num a) => a -> a
powerOfTwo n
    | n .&. (n - 1) == 0 = n `shiftR` 1
    | otherwise = go n
 where
    go w = if w .&. (w - 1) == 0 then w else go (w .&. (w - 1))
{-# INLINE powerOfTwo #-}
