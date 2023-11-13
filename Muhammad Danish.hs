{-# LANGUAGE OverloadedStrings #-}

import Network.Google (runGoogle)
import Network.Google.Search.Custom (search, CustomSearchCseId(..), CustomSearchApiKey(..), Search(..), Item(..))
import Data.Text (unpack)
import System.Random
import Data.List
import Data.Char

-- Function to perform a Google search and return the top 5 URLs
googleSearch :: String -> IO [String]
googleSearch query = do
  let cseId = CustomSearchCseId "custom-search-engine-id"
      apiKey = CustomSearchApiKey "api-key"
  result <- runGoogle $ search cseId apiKey query
  return $ take 5 $ map (unpack . itemLink . searchItem) $ searchItems result

-- Replace "custom-search-engine-id" and "api-key" with your actual values.
-- You can obtain them by creating a custom search engine on the Google Custom Search Console at https://cse.google.com/cse/


-- Function to generate a random password
generateRandomPassword :: Int -> Bool -> Bool -> IO String
generateRandomPassword length useSymbols useNumbers = do
    allChars <- shuffle <$> generateAllChars
    return $ take length allChars
  where
    generateAllChars = do
        let chars = ['a'..'z'] ++ ['A'..'Z'] ++ (if useSymbols then "!@#$%^&*()_+-=[]{}|;':,.<>?/" else "")
                    ++ (if useNumbers then "0123456789" else "")
        return chars

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

main :: IO ()
main = do
    let passwordLength = 8
    let includeSymbols = True
    let includeNumbers = True
    let generatedPassword = generateRandomPassword passwordLength includeSymbols includeNumbers
    putStrLn $ "Generated Password: " ++ generatedPassword

    let keyword = "secure"
    let passwordWithKeyword = includeKeyword keyword generatedPassword
    putStrLn $ "Password with Keyword: " ++ passwordWithKeyword
