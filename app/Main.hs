{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE CPP #-}

module Main where

import Universum

import qualified Data.List.NonEmpty as NE
import qualified Data.Vector as V
import Crypto.Hash
import qualified Cardano.Crypto.Wallet as CC
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL

import qualified Data.Store as S
import Data.Store as S hiding (decode, encode)

import qualified Data.Binary.Serialise.CBOR as C
import Data.Binary.Serialise.CBOR as C hiding (decode, encode)

import Criterion
import Criterion.Main
import Weigh

import Types
import Coin
import Store
import Cbor

main = mainbench

{- Weigh
~~~~~~~~

mainweigh = mainWith $ do
    func "cbor/tx" (C.serialise . C.deserialise @Tx) (force (C.serialise tx))
    func "store/tx" (S.encode . S.decodeEx @Tx) (force (S.encode tx))

    func "cbor/addr" (C.serialise . C.deserialise @Address) (force (C.serialise addr))
    func "store/addr" (S.encode . S.decodeEx @Address) (force (S.encode addr))

    func "cbor/hash" (C.serialise . C.deserialise @Hash) (force (C.serialise h))
    func "store/hash" (S.encode . S.decodeEx @Hash) (force (S.encode h))
-}

mainbench :: IO ()
mainbench = defaultMain
    [ bgroup "100000 varints"
      [ bench "store" $ nf (recodestore @[Varint]) (S.encode (map Varint [1..100000]))
      , bench "cbor"  $ nf (recodecbor @[Word]) (C.serialise [1..100000 :: Word64])
      ]
    , bgroup "10000 empty blocks"
      [ bench "store" $ nf (recodestore @[Block]) (S.encode $ replicate 10000 emptyBlock)
      , bench "cbor"  $ nf (recodecbor @[Block]) (C.serialise $ replicate 10000 emptyBlock)
      ]
    , bgroup "3000 small blocks"
      [ bench "store" $ nf (recodestore @[Block]) (S.encode $ replicate 3000 (smallBlock True))
      , bench "cbor"  $ nf (recodecbor @[Block]) (C.serialise $ replicate 3000 (smallBlock False))
      ]
    , bgroup "1000 medium blocks"
      [ bench "store" $ nf (recodestore @[Block]) (S.encode $ replicate 1000 (mediumBlock True))
      , bench "cbor"  $ nf (recodecbor @[Block]) (C.serialise $ replicate 1000 (mediumBlock False))
      ]
    , bgroup "50 large blocks"
      [ bench "store" $ nf (recodestore @[Block]) (S.encode $ replicate 50 (largeBlock True))
      , bench "cbor"  $ nf (recodecbor @[Block]) (C.serialise $ replicate 50 (largeBlock False))
      ]
    , bgroup "10000 transactions"
      [ bench "store" $ nf (recodestore @[Tx]) (S.encode $ replicate 10000 tx)
      , bench "cbor"  $ nf (recodecbor @[Tx]) (C.serialise $ replicate 10000 tx)
      ]
    ]

recodecbor :: forall a. Serialise a => LByteString -> LByteString
recodecbor = C.serialise . C.deserialise @a

recodestore :: forall a. Store a => ByteString -> ByteString
recodestore = S.encode . S.decodeEx @a

----------------------------------------------------------------------------
-- Data for benchmarks
----------------------------------------------------------------------------

emptyBlock :: Block
emptyBlock = Block
    { _mbTxPayload = UnsafeTxPayload
          { _txpTxs = mkMerkleTreeStore []
          , _txpWitnesses = []
          , _txpDistributions = []
          }
    , _mbMpc = CommitmentsPayload mempty mempty
    }

smallBlock :: Bool -> Block
smallBlock s = Block
    { _mbTxPayload = UnsafeTxPayload
          { _txpTxs = (if s then mkMerkleTreeStore else mkMerkleTreeCbor) $ replicate 5 tx
          , _txpWitnesses = replicate 5 txwit
          , _txpDistributions = replicate 5 txdistr
          }
    , _mbMpc = CommitmentsPayload mempty mempty
    }

mediumBlock :: Bool -> Block
mediumBlock s = Block
    { _mbTxPayload = UnsafeTxPayload
          { _txpTxs = (if s then mkMerkleTreeStore else mkMerkleTreeCbor) $ replicate 100 tx
          , _txpWitnesses = replicate 100 txwit
          , _txpDistributions = replicate 100 txdistr
          }
    , _mbMpc = CommitmentsPayload mempty mempty
    }

largeBlock :: Bool -> Block
largeBlock s = Block
    { _mbTxPayload = UnsafeTxPayload
          { _txpTxs = (if s then mkMerkleTreeStore else mkMerkleTreeCbor) $ replicate 2000 tx
          , _txpWitnesses = replicate 2000 txwit
          , _txpDistributions = replicate 2000 txdistr
          }
    , _mbMpc = CommitmentsPayload mempty mempty
    }

h = hash ("" :: ByteString)
addr = PubKeyAddress h (Attributes (AddrPkAttrs Nothing) "")
txin = TxIn h 0
txout = TxOut addr (Coin 25000000)
txinwit = PkWitness
    ((\(Right x) -> x) $ CC.xpub (BS.replicate 64 0xAB))
    ((\(Right x) -> x) $ CC.xsignature (BS.replicate 64 0xAB))
txwit = V.fromList [txinwit, txinwit, txinwit]
txoutdistr = []
txdistr = NE.fromList [txoutdistr, txoutdistr]
tx = UnsafeTx
         { _txInputs = NE.fromList [txin, txin, txin]
         , _txOutputs = NE.fromList [txout, txout]
         , _txAttributes = Attributes () "" }
