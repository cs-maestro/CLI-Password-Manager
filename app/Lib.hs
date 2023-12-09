-- Lib.hs

module Lib
    ( boyerMooreSearch
    , generateRandomPassword
    , googleSearch
    , searchByKeyword
    , websiteLookup
    ) where

import Data.List
import Data.Maybe (fromMaybe)
import System.IO
import System.Random
import Control.Monad (void)


boyerMooreSearch :: Eq a => [a] -> [a] -> [Int]
boyerMooreSearch needle haystack = search 0
  where
    search i
      | i + len > length haystack = []
      | needle == chunk = i : search (i + len)
      | otherwise = search (i + max 1 (offset chunk needle))
      where
        len = length needle
        chunk = take len (drop i haystack)
        offset xs ys = length (takeWhile (/= ys) (inits xs))

data UsernameCategory = Email | Phone | Username | Misc deriving (Show, Eq)
data Account = Account
  { website :: String
  , username :: String
  , usernameCategory :: UsernameCategory
  , password :: String
  , customName :: String
  } deriving (Show, Eq)

googleSearch :: String -> IO [String]
googleSearch query = do
  -- Placeholder for the actual implementation
  putStrLn $ "Searching Google for: " ++ query
  return ["www.example.com", "www.sample.com", "www.test.com", "www.demo.com", "www.xyz.com"]

generateRandomPassword :: Bool -> Bool -> Int -> IO String
generateRandomPassword useSymbols useNumbers length' = do
  gen <- newStdGen
  let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
      numbers = "0123456789"
      chars = ['a'..'z'] ++ ['A'..'Z'] ++ (if useSymbols then symbols else "") ++ (if useNumbers then numbers else "")
      password = map (chars !!) $ take length' $ randomRs (0, length chars - 1) gen
  return password




  