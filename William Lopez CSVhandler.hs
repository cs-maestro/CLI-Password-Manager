module Main where
import System.Directory
import Data.List.Split
import EncryptionIO
import Encrypter
import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString as BNL
import Data.Binary.Get
import Data.Binary.Put

data UsernameData = Username String | Email String | PhoneNumber String deriving (Eq)

instance Show UsernameData where
    show (Username xs) = "Username: " ++ xs
    show (Email xs) = "Email: " ++ xs
    show (PhoneNumber xs) = "Phone Number: " ++ xs

data PassInfo = PassInfo
    {
    username :: [UsernameData],
    password :: String,
    website :: String,
    url :: String
    } deriving (Eq)

instance Show PassInfo where
    show (PassInfo username password website url) =
        "\n\nWebsite: " ++ website ++ "\nURL: " ++ url ++
        "\nLogin Info: " ++ (show username) ++ "\nPassword: " ++ password ++ "\nPassword Strength = " ++ (getPasswordStrength password) ++ "\n"

main :: IO ()
main = do
    putStr "Haskel Password Manager:\n"
    dfe <- doesFileExist "resources\\encInfo.bin"
    if (dfe == False)
        then do 
            newMasterPassword <- passwordLengthLoop
            salt <- generateSalt
            passDigest <- generatePassDigest newMasterPassword salt
            createDirectoryIfMissing False "resources"
            writeBin salt (digestPassHash passDigest)
            handleLoop []
            
            let key = mkVec (runGet (V.replicateM 4 getWord32host) (BNL.fromStrict (digestKey passDigest))) :: Word128
            encryptFile "resources\\info.txt" "resources\\encInfo.bin" key
            removeFile "resources\\info.txt"
        else do
            binData <- readBin
            key <- passwordLoop binData
            decryptFile "resources\\encInfo.bin" "resources\\info.txt" key
            tsv <- readFile "resources\\info.txt"
            let stl = stringToList tsv
            let importedInfoList = createPassInfoList stl
            handleLoop importedInfoList
            
            encryptFile "resources\\info.txt" "resources\\encInfo.bin" key
            removeFile "resources\\info.txt"
    where
        passwordLoop :: BinData -> IO Word128
        passwordLoop binData = do
            putStr "Please enter the master password.\n"
            userMasterPassword <- getLine
            passDigest <- generatePassDigest userMasterPassword $ binSalt binData
            if (binPassHash binData) == (digestPassHash passDigest)
                then pure (mkVec (runGet (V.replicateM 4 getWord32host) (BNL.fromStrict (digestKey passDigest))) :: Word128)
                else do
                        putStr "Incorrect password.\n"
                        passwordLoop binData
        passwordLengthLoop :: IO String
        passwordLengthLoop = do
            putStr "Set a master password between 10-128 characters.\n"
            newMasterPassword <- getLine
            if (length newMasterPassword) < 10
                then do 
                    putStr "Password is too short.\n"
                    passwordLengthLoop
                else if (length newMasterPassword) > 128
                    then do
                        putStr "Password is too long.\n"
                        passwordLengthLoop
                    else pure $ newMasterPassword


handleLoop :: [PassInfo] -> IO ()
handleLoop masterList = do
    putStr ("\nThere are " ++ (show (length masterList)) ++ " passwords saved.\n")
    putStr "Enter a Command\n"
    putStr "All|Add|Delete|Get|Import|Export|Save|Quit\n"
    nextCommand <- getLine
    if (nextCommand == "Quit")
        then putStr "Goodbye\n"
        else case nextCommand of
            "All" -> do
                putStr (show masterList)
                handleLoop masterList
            "Add" -> do 
                newusernames <- (getUsernamesFromUser [])
                putStr("Enter a website.\n")
                newWebsite <- getLine
                putStr("Enter a URL.\n")
                newURL <- getLine
                putStr("Enter a password.\n")
                newPassword <- getLine
                if (duplicateInfo (masterList ++ [(PassInfo newusernames newPassword newWebsite newURL)]))
                    then do 
                        putStr("This Information already exists.\n")
                        handleLoop masterList
                    else handleLoop (masterList ++ [(PassInfo newusernames newPassword newWebsite newURL)])
            "Delete" -> do
                putStr("Enter a website.\n")
                websiteToDelete <- getLine
                putStr("Enter a password.\n")
                passwordToDelete <- getLine
                handleLoop (deleteFromInfoList websiteToDelete passwordToDelete masterList)
            "Get" -> do 
                putStr ("Enter a username.\n")
                line <- getLine
                putStr (show (fetchFromUsername line masterList))
                handleLoop masterList
            "Import" -> do
                putStr("Please enter a file path.\n")
                filePath <- getLine
                newInfo <- readFile filePath
                handleLoop (dropDuplicateInfo (masterList ++ (createPassInfoList (stringToList newInfo))))
            "Export" -> do
                putStr("Please enter a file path.\n")
                filePath <- getLine
                exportPasswordInfo filePath masterList
                handleLoop masterList
            "Save" -> do
                exportPasswordInfo "resources\\info.txt" masterList
                handleLoop masterList
            dfault -> do
                putStr("Command not recognized.\n")
                handleLoop masterList

-- Gets a list of UsernameData from the user
getUsernamesFromUser :: [UsernameData] -> IO [UsernameData]
getUsernamesFromUser acc = do
    putStr("Do you login with a 'Username', 'Email', 'Phonenumber'.\n")
    putStr("This will repeat until 'Done' entered.\n")
    newUsernameType <- getLine
    case newUsernameType of
        "Done" -> return acc
        "Username" -> do
            putStr("Enter the username.\n")
            newUsername <- getLine
            getUsernamesFromUser (acc ++ [(Username newUsername)])
        "Email" -> do
            putStr("Enter the email.\n")
            newUsername <- getLine
            getUsernamesFromUser (acc ++ [(Email newUsername)])
        "Phonenumber" -> do
            putStr("Enter the phonenumber.\n")
            newUsername <- getLine
            getUsernamesFromUser (acc ++ [(PhoneNumber newUsername)])
        dfault -> getUsernamesFromUser acc

-- Decomposes tab seperated values into a list of lists of strings.
stringToList xs = (map (filter (/= "")) (map (splitOn "\t") (lines xs)))

-- Reduces a PassInfo into a string seperated by tabs.
passInfoToString :: PassInfo -> String
passInfoToString (PassInfo username password website url) = 
    password ++ "\t" ++ website ++ "\t" ++ url ++ "\t" ++ (destruct username)
    where
        destruct :: [UsernameData] -> String
        destruct [] = []
        destruct (x:xs) = case x of
            (Username s) -> "username" ++ "\t" ++ s ++ "\t" ++ (destruct xs)
            (Email s) -> "email" ++ "\t" ++ s ++ "\t" ++ (destruct xs)
            (PhoneNumber s) -> "phone" ++ "\t" ++ s ++ "\t" ++ (destruct xs)

-- Gets PassInfo who's username is equal to the given string.
fetchFromUsername :: String -> [PassInfo] -> [PassInfo]
fetchFromUsername username [] = []
fetchFromUsername username ((PassInfo usernames password website url):xs) = 
    if (hasUsename username usernames)
        then (PassInfo usernames password website url) : (fetchFromUsername username xs)
        else (fetchFromUsername username xs)
    where
        hasUsename :: String -> [UsernameData] -> Bool
        hasUsename username [] = False
        hasUsename username ((Username s):xs) = if (username == s) then True else (hasUsename username xs)
        hasUsename username ((Email s):xs) = if (username == s) then True else (hasUsename username xs)
        hasUsename username ((PhoneNumber s):xs) = if (username == s) then True else (hasUsename username xs)

-- Returns a list of PassInfo without one given a website and password.
deleteFromInfoList :: String -> String -> [PassInfo] -> [PassInfo]
deleteFromInfoList website password [] = []
deleteFromInfoList website password infoList = filter (compareWebAndPass website password) infoList
    where
        compareWebAndPass :: String -> String -> PassInfo -> Bool
        compareWebAndPass web pass (PassInfo usernames password website url) =
            if (web == website)
                then if (pass == password)
                    then False
                    else True
                else True

-- Creates a PassInfo list from a list of lists of strings.
createPassInfoList :: [[String]] -> [PassInfo]
createPassInfoList [] = []
createPassInfoList (x:xs) = 
    (PassInfo (getUsernames (drop 3 x)) (x!!0) (x!!1) (x!!2) ) : createPassInfoList xs
    where
        getUsernames :: [String] -> [UsernameData]
        getUsernames [] = []
        getUsernames (x:(y:xs)) =
            case x of
                "username" -> (Username y) : getUsernames (xs)
                "email" -> (Email y) : getUsernames (xs)
                "phone" -> (PhoneNumber y) : getUsernames (xs)

-- Returns true is there is duplicate PassInfo in a list.
duplicateInfo :: [PassInfo] -> Bool
duplicateInfo [] = False
duplicateInfo (x:xs) =
    if (elem x xs)
        then True
        else duplicateInfo xs

dropDuplicateInfo :: [PassInfo] -> [PassInfo]
dropDuplicateInfo [] = []
dropDuplicateInfo (x:xs) =
    if (elem x xs)
        then dropDuplicateInfo xs
        else x : dropDuplicateInfo xs



-- Converts a string to an integer value.
-- takes the string and 0 as an input.
getPasswordStrength :: String -> String
getPasswordStrength pass = 
    if ((passwordToNumber pass 0) > 50)
        then "strong"
        else if ((passwordToNumber pass 0) > 25)
            then "medium"
            else if ((passwordToNumber pass 0) > 10)
                then "weak"
                else "very weak"
    where
        passwordToNumber :: String -> Int -> Int
        passwordToNumber [] acc = acc
        passwordToNumber (x:xs) acc = 
            if (elem x "!@#$%^&*()_-~`+=<>?:{}|,./\\;\'[]\"")
                then passwordToNumber xs (acc + 12)
                else if (elem x "1234567890")
                    then passwordToNumber xs (acc + 6)
                    else passwordToNumber xs (acc + 3)

-- Exports a list of PassInfo to a file.
-- takes a file path and list of PassInfo.
exportPasswordInfo :: String -> [PassInfo] -> IO()
exportPasswordInfo path xs = writeFile path (listToString xs "")

-- Converts a list of PassInfo to an exportable string.
-- takes a list of PassInfo and an empty list as input.
listToString :: [PassInfo] -> String -> String
listToString [] acc = acc
listToString (x:xs) acc = 
    acc ++ (passInfoToString x) ++ "\n" ++ (listToString xs acc)
