{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Lib.File where

import Control.Exception
import Crypto.Number.Basic
import Crypto.Number.Serialize
import Crypto.PubKey.RSA
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL
import Data.Maybe
import Data.PEM
import Data.Text.Encoding (decodeUtf8)
import Data.X509
import Data.X509.File (PEMError (..))
import Lib.Types
import System.FilePath

readPEMs :: FilePath -> IO [PEM]
readPEMs filepath = do
  content <- BS.readFile filepath
  either (throw . PEMError) return $ pemParseBS content

pemToPubKey :: [Maybe PubKey] -> PEM -> [Maybe PubKey]
pemToPubKey acc PEM{..} =
  case decodeASN1' BER pemContent of
    Left _ -> acc
    Right asn1 -> case pemName of
      "PUBLIC KEY" -> tryRSA asn1 : acc
      _ -> acc
 where
  tryRSA asn1 = case rsaFromASN1 asn1 of
    Left _ -> Nothing
    Right (k, _) -> Just (PubKeyRSA k)

readPubKeyFile :: FilePath -> IO [PubKey]
readPubKeyFile path = catMaybes . foldl' pemToPubKey [] <$> readPEMs path

rsaFromASN1 :: [ASN1] -> Either String (PublicKey, [ASN1])
rsaFromASN1 (Start Sequence : IntVal n : IntVal e : xs) = Right (PublicKey (numBytes n) n e, xs)
rsaFromASN1
  ( Start Sequence
      : Start Sequence
      : OID [1, 2, 840, 113549, 1, 1, 1]
      : Null
      : End Sequence
      : BitString bs
      : xs
    ) =
    let inner = either strError rsaFromASN1 $ decodeASN1' BER (bitArrayGetData bs)
        strError = Left . ("rsaFromASN1: RSA.PublicKey: " ++) . show
     in either Left (\(k, _) -> Right (k, xs)) inner
rsaFromASN1 _ = Left "rsaFromASN1: unexpected format"

-- | scuffed jwks that only supports rsa
readKeys :: [FilePath] -> IO [JWK]
readKeys keys = do
  ks <- traverse (fmap <$> (,) <*> readPubKeyFile) keys

  return $
    foldl'
      ( \acc (kp, pks) -> case pks of
          PubKeyRSA (PublicKey{..}) : _ ->
            ( JWKRSA
                { kty = "RSA"
                , alg = "RS256"
                , kid = takeBaseName kp
                , n = (decodeUtf8 . encodeUnpadded) (i2osp public_n)
                , e = (decodeUtf8 . encodeUnpadded) (i2osp public_e)
                }
                : acc
            )
          _ -> acc
      )
      []
      ks
