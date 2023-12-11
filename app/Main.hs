-- Main.hs

module Main where

import Encrypter
import EncryptionIO
import CSVHandler
import System.Exit
import Control.Monad (void)
import Lib
import System.Directory
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString as BNL
import System.IO

main :: IO ()
main = do
    putHeader
    dfe <- doesFileExist "resources\\encInfo.bin"
    if (dfe == False)
        then do 
            newMasterPassword <- newPasswordLoop
            salt <- generateSalt
            passDigest <- generatePassDigest newMasterPassword salt
            createDirectoryIfMissing False "resources"
            writeBin "resources\\data.bin" salt (digestPassHash passDigest)
            handleLoop []
            
            let key = mkVec (runGet (V.replicateM 4 getWord32host) (BNL.fromStrict (digestKey passDigest))) :: Word128
            encryptFile "resources\\info.txt" "resources\\encInfo.bin" key
            removeFile "resources\\info.txt"
        else do
            binData <- readBin "resources\\data.bin"
            key <- passwordLoop binData
            decryptFile "resources\\encInfo.bin" "resources\\info.txt" key
            tsv <- readFile "resources\\info.txt"
            let stl = stringToList tsv
            let importedInfoList = createPassInfoList stl
            handleLoop importedInfoList
            
            encryptFile "resources\\info.txt" "resources\\encInfo.bin" key
            removeFile "resources\\info.txt"
    where
        newPasswordLoop :: IO String
        newPasswordLoop = do
            putStr "Set a master password between 10-128 characters:\n"
            hSetBuffering stdin NoBuffering
            hSetEcho stdin False
            newPassword <- getLine
            hSetBuffering stdin LineBuffering
            hSetEcho stdin True
            if (length newPassword) < 10
                then do 
                    putStr "Password is too short. Please try again.\n\n"
                    newPasswordLoop
                else if (length newPassword) > 128
                    then do
                        putStr "Password is too long.Please try again\n\n"
                        newPasswordLoop
                    else do
                        putStr "Enter the password again:\n"
                        hSetBuffering stdin NoBuffering
                        hSetEcho stdin False
                        newPassword2 <- getLine
                        hSetBuffering stdin LineBuffering
                        hSetEcho stdin True
                        if newPassword == newPassword2
                            then strengthLoop newPassword
                            else do
                                putStr "Sorry, the password's didn't match.\n\n"
                                newPasswordLoop
        strengthLoop :: String -> IO String
        strengthLoop newPassword = do
            let ps = getPasswordStrength newPassword
            if ps < Strong
                then do
                    putStr $ "Your password has " ++ (show ps) ++ " strength.\n"
                    putStr "Warning: Your master password is what protects all your other passwords, so it should be strong.\n"
                    putStr "Consider adding special characters, numbers, upper and lowercase characters, or increasing its length.\n"
                    putStr "Are you sure you wish to proceed?\n"
                    yn <- yesNoLoop
                    if yn
                        then pure newPassword
                        else newPasswordLoop
                else pure newPassword

putHeader :: IO ()
putHeader = do
    putStrLn " ________________________________________________________________________________________________________________"
    putStrLn "/                                                                                                                \\"
    putStrLn "|                                                                                                                |"
    putStrLn "|  ██████╗ ███████╗██╗  ████████╗ █████╗     ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗  |"
    putStrLn "|  ██╔══██╗██╔════╝██║  ╚══██╔══╝██╔══██╗    ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗ |"
    putStrLn "|  ██║  ██║█████╗  ██║     ██║   ███████║    ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║ |"
    putStrLn "|  ██║  ██║██╔══╝  ██║     ██║   ██╔══██║    ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║ |"
    putStrLn "|  ██████╔╝███████╗███████╗██║   ██║  ██║    ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝ |"
    putStrLn "|  ╚═════╝ ╚══════╝╚══════╝╚═╝   ╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝  |"
    putStrLn "|                                                                                                                |"
    putStrLn "|                        ███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗                           |"
    putStrLn "|                        ████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗                          |"
    putStrLn "|                        ██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝                          |"
    putStrLn "|                        ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗                          |"
    putStrLn "|                        ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║                          |"
    putStrLn "|                        ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝                          |"
    putStrLn "|                                                                                                                |"
    putStrLn "\\________________________________________________________________________________________________________________/"
    putStrLn "// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * \\"
    putStrLn "*                                     A Terminal-Based Password Manager                                         *"
    putStrLn "*                                              Version: v1.0                                                    *"
    putStrLn "*                       Github: https://github.com/cs-maestro/CLI-Password-Manager.git                          *"
    putStrLn "\\ * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //"

{-
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

      generatedPassword <- generateRandomPassword passwordLength includeSymbols includeNumbers

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
-}
