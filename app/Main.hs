{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Monad
import Lib.File
import Lib.Types
import Network.Wai.Middleware.RequestLogger
import Options.Applicative
import System.Directory
import System.FilePath
import Web.Scotty

data Config
  = Config
  { port :: Int
  , keyDir :: FilePath
  }

configParser :: Parser Config
configParser =
  Config
    <$> option
      auto
      ( long "port"
          <> short 'p'
          <> showDefault
          <> value 3000
          <> metavar "PORT"
      )
    <*> argument str (metavar "KEY_DIR")

main :: IO ()
main = do
  Config{..} <- execParser $ info (configParser <**> helper) fullDesc

  keys <-
    fmap (keyDir </>) <$> listDirectory keyDir
      >>= filterM doesFileExist
      >>= readKeys

  scotty port $ do
    middleware logStdoutDev

    get "/.well-known/jwks.json" $ do
      json $ JWKS{..}
