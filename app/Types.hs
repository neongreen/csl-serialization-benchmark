{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Types where


import Universum

import qualified Cardano.Crypto.Wallet as CC

import qualified Data.ByteArray as ByteArray
import Data.Vector (Vector)
import Crypto.Hash (Digest, Blake2s_256)
import qualified Data.Foldable
import Data.Hashable hiding (hash)
import System.IO.Unsafe (unsafeDupablePerformIO)


----------------------------------------------------------------------------
-- Block and its components
----------------------------------------------------------------------------

data Block = Block
    { _mbTxPayload        :: !TxPayload
    , _mbMpc              :: !GtPayload
    -- , _mbProxySKs      :: ![ProxySKHeavy]
    -- , _mbUpdatePayload :: !UpdatePayload
    } deriving (Eq, Generic, Typeable)

data TxPayload = UnsafeTxPayload
    { _txpTxs           :: !(MerkleTree Tx)
    , _txpWitnesses     :: ![TxWitness]
    , _txpDistributions :: ![TxDistribution]
    } deriving (Eq, Generic)

data GtPayload
    = CommitmentsPayload  !CommitmentsMap !VssCertificatesMap
    -- OpeningsPayload     !OpeningsMap    !VssCertificatesMap
    -- SharesPayload       !SharesMap      !VssCertificatesMap
    -- CertificatesPayload !VssCertificatesMap
    deriving (Eq, Generic)

----------------------------------------------------------------------------
-- Transaction-related types
----------------------------------------------------------------------------

data Tx = UnsafeTx
    { _txInputs     :: !(NonEmpty TxIn)
    , _txOutputs    :: !(NonEmpty TxOut)
    , _txAttributes :: !TxAttributes
    } deriving (Eq, Ord, Generic, Typeable)

data TxIn = TxIn
    { txInHash  :: !TxId
    , txInIndex :: !Word32
    } deriving (Eq, Ord, Generic, Typeable)

data TxOut = TxOut
    { txOutAddress :: !Address
    , txOutValue   :: !Coin
    } deriving (Eq, Ord, Generic, Typeable)

type TxAttributes = Attributes ()

type TxId = Hash

type TxWitness = Vector TxInWitness

data TxInWitness
    = PkWitness { twKey :: !CC.XPub
                , twSig :: !CC.XSignature }
    | ScriptWitness { twValidator :: !Script
                    , twRedeemer  :: !Script }
    -- RedeemWitness { twRedeemKey :: !RedeemPublicKey
    --               , twRedeemSig :: !(RedeemSignature TxSigData) }
    | UnknownWitnessType !Word8 !ByteString
    deriving (Eq, Generic, Typeable)

type TxDistribution = NonEmpty TxOutDistribution

type TxOutDistribution = [(StakeholderId, Coin)]

----------------------------------------------------------------------------
-- MPC-related types
----------------------------------------------------------------------------

type CommitmentsMap = HashMap StakeholderId SignedCommitment
type VssCertificatesMap = HashMap StakeholderId VssCertificate
type SignedCommitment = (CC.XPub, Commitment, CC.XSignature)

data VssCertificate = VssCertificate
    { vcVssKey      :: !ByteString -- VssPublicKey
    , vcExpiryEpoch :: !Word64
    , vcSignature   :: !CC.XSignature
    , vcSigningKey  :: !CC.XPub
    } deriving (Eq, Generic)

data Commitment = Commitment
    { commExtra  :: !ByteString -- SecretSharingExtra
    , commProof  :: !ByteString -- SecretProof
    , commShares :: !(HashMap ByteString (NonEmpty ByteString))
        -- (HashMap VssPublicKey (NonEmpty EncShare))
    } deriving (Eq, Generic)

----------------------------------------------------------------------------
-- Addresses
----------------------------------------------------------------------------

data Address
    = PubKeyAddress
          { addrKeyHash      :: !Hash
          , addrPkAttributes :: !(Attributes AddrPkAttrs) }
    | ScriptAddress
          { addrScriptHash :: !Hash }
    -- RedeemAddress
    --    { addrRedeemKeyHash :: !(AddressHash RedeemPublicKey) }
    | UnknownAddressType !Word8 !ByteString
    deriving (Eq, Ord, Generic, Typeable)

newtype AddrPkAttrs = AddrPkAttrs
    { addrPkDerivationPath :: Maybe HDAddressPayload
    } deriving (Eq, Ord, Generic, Typeable)

type HDAddressPayload = ByteString

----------------------------------------------------------------------------
-- Merkle tree
----------------------------------------------------------------------------

data MerkleTree a = MerkleEmpty | MerkleTree Word32 (MerkleNode a)
    deriving (Eq, Generic)

instance Foldable MerkleTree where
    foldMap _ MerkleEmpty      = mempty
    foldMap f (MerkleTree _ n) = foldMap f n

    null MerkleEmpty = True
    null _           = False

    length MerkleEmpty      = 0
    length (MerkleTree s _) = fromIntegral s

data MerkleNode a
    = MerkleBranch { mRoot  :: MerkleRoot a
                   , mLeft  :: MerkleNode a
                   , mRight :: MerkleNode a}
    | MerkleLeaf { mRoot :: MerkleRoot a
                 , mVal  :: a}
    deriving (Eq, Generic)

instance Foldable MerkleNode where
    foldMap f x = case x of
        MerkleLeaf{mVal}            -> f mVal
        MerkleBranch{mLeft, mRight} ->
            foldMap f mLeft `mappend` foldMap f mRight

type MerkleRoot a = Hash

----------------------------------------------------------------------------
-- Miscellaneous types
----------------------------------------------------------------------------

type Hash = Digest Blake2s_256

instance Hashable Hash where
    hashWithSalt s h =
        unsafeDupablePerformIO $
        ByteArray.withByteArray h (\ptr -> hashPtrWithSalt ptr len s)
      where
        !len = ByteArray.length h

data Attributes h = Attributes
    { attrData   :: h
    , attrRemain :: ByteString
    } deriving (Eq, Ord, Generic, Typeable)

type StakeholderId = Hash

newtype Coin = Coin
    { getCoin :: Word64
    } deriving (Ord, Eq, Generic, Hashable)

instance Bounded Coin where
    minBound = Coin 0
    maxBound = Coin 45000000000000000

data Script = Script
    { scrVersion :: !Word16
    , scrScript  :: !LByteString
    } deriving (Eq, Generic, Typeable)

----------------------------------------------------------------------------
-- Varints (to check how store will handle them)
----------------------------------------------------------------------------

newtype Varint = Varint {getVarint :: Word64}
