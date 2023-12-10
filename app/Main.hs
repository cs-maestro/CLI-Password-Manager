-- Main.hs

module Main where

import System.Exit
import Control.Monad (void)
import Lib

main :: IO ()
main = do
    putStrLn "Welcome to the Password Manager CLI!"
    putStrLn "1. Search by keyword"
    putStrLn "2. Validate Website URL"
    putStrLn "3. Generate random password"
    putStrLn "4. Exit"
    putStrLn "Choose an option (1-4):"

    choice <- getLine
    case choice of
        "1" -> searchByKeyword >> main
        "2" -> validateWebsiteURL >> main
        "3" -> generateRandomPasswordCLI >> main
        "4" -> exitSuccess
        _   -> putStrLn "Invalid choice." >> main

generateRandomPasswordCLI :: IO ()
generateRandomPasswordCLI = do
  putStrLn "1. Generate a new password"
  putStrLn "2. Back to main menu"
  putStrLn "Choose an option (1-2):"
  choice <- getLine
  case choice of
    "1" -> do
      putStrLn "Include symbols in the password? (yes/no)"
      useSymbols <- getLine
      putStrLn "Include numbers in the password? (yes/no)"
      useNumbers <- getLine
      putStrLn "Enter password length:"
      passwordLength <- readLn

      let includeSymbols = useSymbols == "yes"
          includeNumbers = useNumbers == "yes"

      generatedPassword <- generateRandomPassword passwordLength

      putStrLn $ "Generated password: " ++ generatedPassword
      generateRandomPasswordCLI
    "2" -> main
    _   -> putStrLn "Invalid choice." >> generateRandomPasswordCLI

searchByKeyword :: IO ()
searchByKeyword = do
  putStrLn "1. Search for a keyword"
  putStrLn "2. Back to main menu"
  putStrLn "Choose an option (1-2):"
  choice <- getLine
  case choice of
    "1" -> do
      putStrLn "Enter search keyword:"
      keyword <- getLine

      let haystack = "This is a sample text with a keyword. This keyword is used as an example."
      let positions = boyerMooreSearch keyword haystack
      putStrLn $ "Keyword found at positions: " ++ show positions
      searchByKeyword
    "2" -> main
    _   -> putStrLn "Invalid choice." >> searchByKeyword

validateWebsiteURL :: IO ()
validateWebsiteURL = do
  putStrLn "1. Validate a URL"
  putStrLn "2. Back to main menu"
  putStrLn "Choose an option (1-2):"
  choice <- getLine
  case choice of
    "1" -> do
      putStrLn "Enter a URL:"
      url <- getLine

      if validateURL url
          then putStrLn "Valid URL."
          else putStrLn "Invalid URL."
      validateWebsiteURL
    "2" -> main
    _   -> putStrLn "Invalid choice." >> validateWebsiteURL
