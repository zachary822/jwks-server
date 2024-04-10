{-# LANGUAGE DeriveGeneric #-}

module Lib.Types where

import Data.Aeson
import Data.Text (Text)
import GHC.Generics

data JWKS = JWKS
  { keys :: ![JWK]
  }
  deriving (Generic, Show, Eq)

instance ToJSON JWKS where
  toEncoding = genericToEncoding defaultOptions

data JWK = JWKRSA
  { kty :: !Text
  , n :: !Text
  , e :: !Text
  , alg :: !Text
  , kid :: !String
  }
  deriving (Generic, Show, Eq)

instance ToJSON JWK where
  toEncoding = genericToEncoding defaultOptions
