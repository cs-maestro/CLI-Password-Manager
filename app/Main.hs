-- Main.hs

module Main where

import System.IO
import System.Exit
import System.Random
import Control.Monad (void)


import Encrypter
import EncryptionIO
import Lib
import CSVHandler

main :: IO ()
main = do
  putStrLn "Welcome to the Password Manager CLI!"
  putStrLn "1. Search by keyword"
  putStrLn "2. Website lookup"
  putStrLn "3. Generate random password"
  putStrLn "4. Exit"
  putStrLn "Choose an option (1-4):"

  choice <- getLine
  case choice of
    "1" -> searchByKeyword
    "2" -> websiteLookup
    "3" -> generateRandomPasswordCLI
    "4" -> exitSuccess
    _   -> putStrLn "Invalid choice." >> main

generateRandomPasswordCLI :: IO ()
generateRandomPasswordCLI = do
  putStrLn "Include symbols in the password? (yes/no)"
  useSymbols <- getLine
  putStrLn "Include numbers in the password? (yes/no)"
  useNumbers <- getLine
  putStrLn "Enter password length:"
  passwordLength <- readLn
  generatedPassword <- generateRandomPassword (useSymbols == "yes") (useNumbers == "yes") passwordLength
  putStrLn $ "Generated password: " ++ generatedPassword

  putStrLn "Press Enter to go back to the main menu."
  void getLine
