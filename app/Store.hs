{-# LANGUAGE DataKinds, TemplateHaskell, ScopedTypeVariables #-}

module Store where

import Universum

import Data.Functor.Contravariant
import qualified Control.Monad as Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteArray as ByteArray
import qualified Cardano.Crypto.Wallet as CC
import Crypto.Hash
import Data.Bits

import qualified Data.Store as S
import Data.Store.Core as S
import Data.Store hiding (decode, encode)
import Data.Store.TH as S
import Data.Store.Internal as S
import TH.Derive

import Types
import Coin (decodeVarint, decodeCoin, hdrToParam, encodeCoin)

-- TODO: ask Vincent whether it could be improved (perhaps with
-- 'ByteArray.withByteArray' and 'pokeFromPtr')
instance Store Hash where
    size = ConstSize 32
    poke digest =
        let bs = ByteArray.convert digest :: ByteString
        in poke (StaticSize @32 bs)
    peek = do
        sbs <- peek
        let bs = unStaticSize @32 sbs :: ByteString
        case digestFromByteString bs of
            Nothing -> error "peek@Hash: impossible"
            Just x  -> pure x
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}

-- 64 = publicKeyLength + chainCodeLength
instance Store CC.XPub where
    size = ConstSize 64
    poke (CC.unXPub -> kc) = poke (StaticSize @64 kc)
    peek = either fail pure . CC.xpub . unStaticSize @64 =<< peek
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}

-- 64 = signatureLength
instance Store CC.XSignature where
    size = ConstSize 64
    poke (CC.unXSignature -> kc) = poke (StaticSize @64 kc)
    peek = either fail pure . CC.xsignature . unStaticSize @64 =<< peek
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}

instance Store Coin where
    size = VarSize (length . encodeCoin)
    poke = mapM_ poke . encodeCoin
    peek = do
        (nbBytes1, acc1) <- hdrToParam <$> peek @Word8
        conts1 <- replicateM nbBytes1 (peek @Word8)
        (nbBytes2, acc2) <- hdrToParam <$> peek @Word8
        conts2 <- replicateM nbBytes2 (peek @Word8)
        --
        either fail pure $ do
            a <- decodeVarint acc1 conts1
            b <- decodeVarint acc2 conts2
            decodeCoin a b
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}

instance Store TxInWitness where
    size = VarSize $ \case
        PkWitness a b     -> 1 + getSize a + getSize b
        ScriptWitness a b -> 1 + getSize a + getSize b
        _ -> error "crap"
    poke = \case
        PkWitness a b -> do
            poke (0 :: Word8)
            poke a
            poke b
        ScriptWitness a b -> do
            poke (1 :: Word8)
            poke a
            poke b
        _ -> error "crap"
    peek = do
        tag <- peek @Word8
        case tag of
            0 -> PkWitness <$> peek <*> peek
            1 -> ScriptWitness <$> peek <*> peek
            _ -> error "crap"
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}

instance Store Address where
    size = VarSize $ \case
        PubKeyAddress a b -> 1 + getSize a + getSize b
        ScriptAddress a   -> 1 + getSize a
        _ -> error "crap"
    poke = \case
        PubKeyAddress a b -> do
            poke (0 :: Word8)
            poke a
            poke b
        ScriptAddress a -> do
            poke (1 :: Word8)
            poke a
        _ -> error "crap"
    peek = do
        tag <- peek @Word8
        case tag of
            0 -> PubKeyAddress <$> peek <*> peek
            1 -> ScriptAddress <$> peek
            _ -> error "crap"
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}

pokeBS :: ByteString -> Poke ()
pokeBS x = do
    let (sourceFp, sourceOffset, sourceLength) = BS.toForeignPtr x
    pokeFromForeignPtr sourceFp sourceOffset sourceLength
{-# INLINE pokeBS #-}

peekBS :: Int -> Peek ByteString
peekBS len = do
    fp <- peekToPlainForeignPtr "ByteString" len
    return (BS.PS fp 0 len)
{-# INLINE peekBS #-}

$($(derive [d|
    instance Deriving (Store Block)
    instance Deriving (Store TxPayload)
    instance Deriving (Store GtPayload)
    instance Deriving (Store AddrPkAttrs)
    instance Store a => Deriving (Store (Attributes a))
    instance Deriving (Store Tx)
    instance Deriving (Store TxIn)
    instance Deriving (Store TxOut)
    instance Deriving (Store Script)
    instance Deriving (Store Commitment)
    instance Deriving (Store VssCertificate)
    |]))

instance Store (MerkleTree Tx) where
    size = contramap toList size
    poke = poke . toList
    peek = mkMerkleTreeStore <$> peek
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}

mkLeafStore :: Store a => a -> MerkleNode a
mkLeafStore a =
    MerkleLeaf
    { mVal  = a
    , mRoot = hash (one 0 <> S.encode a)
    }
{-# INLINE mkLeafStore #-}

mkBranchStore :: MerkleNode a -> MerkleNode a -> MerkleNode a
mkBranchStore a b =
    MerkleBranch
    { mLeft  = a
    , mRight = b
    , mRoot  = hash $ mconcat [ one 1 :: ByteString
                              , ByteArray.convert (mRoot a)
                              , ByteArray.convert (mRoot b) ]
    }
{-# INLINE mkBranchStore #-}

mkMerkleTreeStore :: Store a => [a] -> MerkleTree a
mkMerkleTreeStore [] = MerkleEmpty
mkMerkleTreeStore ls = MerkleTree (fromIntegral lsLen) (go lsLen ls)
  where
    lsLen = length ls
    go _  [x] = mkLeafStore x
    go len xs = mkBranchStore (go i l) (go (len - i) r)
      where
        i = powerOfTwo len
        (l, r) = splitAt i xs

powerOfTwo :: (Bits a, Num a) => a -> a
powerOfTwo n
    | n .&. (n - 1) == 0 = n `shiftR` 1
    | otherwise = go n
 where
    go w = if w .&. (w - 1) == 0 then w else go (w .&. (w - 1))
{-# INLINE powerOfTwo #-}

instance Store Varint where
    size = VarSize $ \(Varint x) ->
        if | x <= 23        -> 1
           | x < 256        -> 2
           | x < 65536      -> 3
           | x < 4294967296 -> 5
           | otherwise      -> 9
    poke (Varint x) =
        if | x <= 23        -> poke (fromIntegral x :: Word8)
           | x < 256        -> poke (24 :: Word8) >>
                               poke (fromIntegral x :: Word8)
           | x < 65536      -> poke (25 :: Word8) >>
                               poke (fromIntegral x :: Word16)
           | x < 4294967296 -> poke (26 :: Word8) >>
                               poke (fromIntegral x :: Word32)
           | otherwise      -> poke (27 :: Word8) >>
                               poke (x :: Word64)
    peek = do
        tag <- peek @Word8
        if | tag <= 23 -> pure (Varint (fromIntegral tag))
           | tag == 24 -> Varint . fromIntegral <$> peek @Word8
           | tag == 25 -> Varint . fromIntegral <$> peek @Word16
           | tag == 26 -> Varint . fromIntegral <$> peek @Word32
           | otherwise -> Varint . fromIntegral <$> peek @Word64
    {-# INLINE size #-}
    {-# INLINE poke #-}
    {-# INLINE peek #-}
