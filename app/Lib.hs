-- Lib.hs

module Lib
    ( boyerMooreSearch
    , generateRandomPassword
    , validateURL
    ) where

import Data.List (isInfixOf, inits)
import System.Random
import Network.URI (URI, parseURI, uriScheme, uriAuthority, uriRegName, uriPath)

validateURL :: String -> Bool
validateURL url =
  case parseURI url of
    Just uri -> hasValidScheme uri && hasValidHostName uri
    Nothing  -> False

hasValidScheme :: URI -> Bool
hasValidScheme uri = uriScheme uri == "http:" || uriScheme uri == "https:" 

hasValidHostName :: URI -> Bool
hasValidHostName uri =
  case uriAuthority uri of
    Just auth -> not (null (uriRegName auth))
    Nothing   -> False

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

generateRandomPassword :: Int -> IO String
generateRandomPassword length' = do
  gen <- newStdGen
  let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
      numbers = "0123456789"
      chars = ['a'..'z'] ++ ['A'..'Z'] ++ symbols ++ numbers
      password = map (chars !!) $ take length' $ randomRs (0, length chars - 1) gen
  return password
