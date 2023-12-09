{-# LANGUAGE OverloadedStrings #-}

import Network.Google (runGoogle)
import Network.Google.Search.Custom (search, CustomSearchCseId(..), CustomSearchApiKey(..), Search(..), Item(..))
import Data.Text (pack, unpack, isInfixOf)
import System.Random
import Data.List
import Data.Char

-- Function to perform a Google search and return the top 5 URLs
googleSearch :: String -> IO [String]
googleSearch query = do
  let cseId = CustomSearchCseId (pack "custom-search-engine-id")
      apiKey = CustomSearchApiKey (pack "api-key")
  result <- runGoogle $ search cseId apiKey query
  return $ take 5 $ map (unpack . itemLink . searchItem) $ searchItems result

-- Function to generate a random password
generateRandomPassword :: Int -> Bool -> Bool -> IO String
generateRandomPassword length useSymbols useNumbers = do
    allChars <- shuffle <$> generateAllChars
    return $ take length allChars
  where
    generateAllChars = do
        let chars = ['a'..'z'] ++ ['A'..'Z'] ++ (if useSymbols then "!@#$%^&*()_+-=[]{}|;':,.<>?/" else "")
                    ++ (if useNumbers then "0123456789" else "")
        return $ chars

    shuffle [] = []
    shuffle xs = do
        index <- randomRIO (0, length xs - 1)
        let (left, right) = splitAt index xs
        head right : shuffle (left ++ tail right)

-- Function to include a keyword in a random place in the password
includeKeyword :: String -> String -> IO String
includeKeyword keyword password = do
    index <- randomRIO (0, length password)
    let (before, after) = splitAt index password
    return $ before ++ keyword ++ after

-- Boyer-Moore search algorithm
boyerMooreSearch :: Eq a => [a] -> [a] -> [Int]
boyerMooreSearch needle haystack = search 0 []
  where
    m = length needle
    n = length haystack

    rightmost = foldl (\m (i, c) -> insertWith (\_ old -> old) c i m) [] (zip [0..] needle)
    go i j
      | j == m = reverse [i..i + m - 1]
      | i >= n = []
      | otherwise =
          let k = case lookup (haystack !! (i + j)) rightmost of
                    Just x -> x
                    Nothing -> m
          in if k == m
               then go (i + j + 1) 0
               else go i (max 1 (j - k))

    search i acc
      | i >= n = acc
      | otherwise =
          let indices = go i 0
          in search (i + 1) (if null indices then acc else indices : acc)

-- Search function for passwords, websites, usernames, and links
searchKeywords :: String -> String -> String -> String -> [Int]
searchKeywords password website username link =
  concatMap (boyerMooreSearch password) ++
  concatMap (boyerMooreSearch website) ++
  concatMap (boyerMooreSearch username) ++
  concatMap (boyerMooreSearch link)
