module CSVHandler where

import System.Directory
import Data.List.Split
import EncryptionIO
import Encrypter
import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString as BNL
import Data.Binary.Get
import Data.Binary.Put
import Data.Char
import System.Hclip
import System.IO

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
        "\nWebsite: " ++ website ++ "\nLogin Info: " ++ (show username) ++ "\n"

data PasswordStrength = Strong | Medium | Weak | VeryWeak
    deriving (Eq)

instance Show PasswordStrength where
    show Strong = "strong"
    show Medium = "medium"
    show Weak = "weak"
    show VeryWeak = "very weak"

instance Ord PasswordStrength where
    Medium <= Strong = True
    Strong <= Medium = False
    Weak <= Medium = True
    Medium <= Weak = False
    VeryWeak <= Weak = True
    Weak <= VeryWeak = False
    Weak <= Strong = True
    Strong <= Weak = False
    VeryWeak <= Strong = True
    Strong <= VeryWeak = False
    VeryWeak <= Medium = True
    Medium <= VeryWeak = False

getUsernameDataStr :: UsernameData -> String
getUsernameDataStr (Username str) = str
getUsernameDataStr (Email str) = str
getUsernameDataStr (PhoneNumber str) = str

showFull :: PassInfo -> String
showFull (PassInfo username password website url) =
    "\n\nWebsite: " ++ website ++ "\nURL: " ++ url ++
    "\nLogin Info: " ++ (show username) ++ "\nPassword: " ++ password ++ "\nPassword Strength = " ++ 
        (show (getPasswordStrength password)) ++ "\n"    

main :: IO ()
main = do
    putStr "Haskel Password Manager:\n"
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

                                

passwordLoop :: BinData -> IO Word128
passwordLoop binData = do
    putStr "Please enter the master password.\n"
    hSetBuffering stdin NoBuffering
    hSetEcho stdin False
    userMasterPassword <- getLine
    hSetBuffering stdin LineBuffering
    hSetEcho stdin True
    passDigest <- generatePassDigest userMasterPassword $ binSalt binData
    if (binPassHash binData) == (digestPassHash passDigest)
        then pure (mkVec (runGet (V.replicateM 4 getWord32host) (BNL.fromStrict (digestKey passDigest))) :: Word128)
        else do
            putStr "Incorrect password.\n"
            passwordLoop binData

handleLoop :: [PassInfo] -> IO ()
handleLoop masterList = do
    putStr ("\nThere are " ++ (show (length masterList)) ++ " passwords saved.\n")
    putStr "Enter a Command\n"
    putStr "All|Add|Search|Import|Export|Quit\n"
    nextCommand <- getLine
    if (nextCommand == "Quit")
        then do
            putStr "Goodbye\n"
            exportPasswordInfo "resources\\info.txt" masterList
        else case nextCommand of
            "All" -> do
                putStr $ concat $ map show masterList
                handleLoop masterList
            "Add" -> do 
                newusernames <- (getUsernamesFromUser [])
                (newWebsite, newURL) <- websiteLoop masterList
                newPassword <- addPasswordLoop masterList
                
                if (duplicateInfo masterList (PassInfo newusernames newPassword newWebsite newURL))
                    then do 
                        putStr("This account already exists.\n")
                        putStr("Please check your passwords again.\n")
                        handleLoop masterList
                    else do
                        handleLoop (masterList ++ [(PassInfo newusernames newPassword newWebsite newURL)])
            "Search" -> handleSearch masterList
            "Import" -> do
                putStr("Please enter a file path for hash bin file.\n")
                fileBinPath <- getLine
                putStr("Please enter a file path for the main data file.\n")
                fileDataPath <- getLine
                imported <- importEncPasswordInfo fileBinPath fileDataPath
                if imported
                    then do
                        newInfo <- readFile "tempImport.txt"
                        let newLs = (dropDuplicateInfo (masterList ++ (createPassInfoList (stringToList newInfo))))
                        exportPasswordInfo "resources\\info.txt" newLs
                        tsv <- readFile "resources\\info.txt"
                        let stl = stringToList tsv
                        let importedInfoList = createPassInfoList stl
                        removeFile "tempImport.txt"
                        handleLoop importedInfoList
                    else do
                        putStr "Unable to import password info.\n"
                        handleLoop masterList
            "Export" -> do
                putStr("Please enter a filname for the hash bin file.\n")
                fileBinPath <- getLine
                putStr("Please enter a filename for the main data file.\n")
                fileDataPath <- getLine
                exportEncPasswordInfo (fileBinPath ++ ".bin") (fileDataPath ++ ".dat") masterList
                handleLoop masterList
            dfault -> do
                putStr("Command not recognized.\n")
                handleLoop masterList

addPasswordLoop :: [PassInfo] -> IO String
addPasswordLoop ls = do
    putStr "Enter a password:\n"
    hSetBuffering stdin NoBuffering
    hSetEcho stdin False
    newPassword <- getLine
    hSetBuffering stdin LineBuffering
    hSetEcho stdin True

    putStr "Please enter the password again:\n"
    hSetBuffering stdin NoBuffering
    hSetEcho stdin False
    newPassword2 <- getLine
    hSetBuffering stdin LineBuffering
    hSetEcho stdin True

    if newPassword == newPassword2
        then do
            let numDupPass = numDuplicatePass ls newPassword
            if numDupPass > 0 
                then do
                    putStr $ "I found " ++ (show numDupPass) ++ " duplicate password(s).\n"
                    putStr "Are you sure you want to proceed with this password?\n"
                    yn <- yesNoLoop
                    if yn
                        then strengthLoop ls newPassword
                        else addPasswordLoop ls
                else strengthLoop ls newPassword
                    
        else do
            putStr "Sorry, these passwords don't match. Try again.\n\n"
            addPasswordLoop ls
    where
        strengthLoop :: [PassInfo] -> String -> IO String
        strengthLoop ls newPassword = do
            let ps = getPasswordStrength newPassword
            if ps < Medium
                then do
                    putStr $ "Your password has " ++ (show ps) ++ " strength.\n"
                    putStr "Consider adding special characters, numbers, upper and lowercase characters, or increasing its length.\n"
                    putStr "Are you sure you wish to proceed?\n"
                    yn <- yesNoLoop
                    if yn
                        then pure newPassword
                        else addPasswordLoop ls
                else pure newPassword

-- Asks user for website nickname and url. If a matching website name is found from
-- the given list, then the corresponding URL is used. Else asks for a url. This url
-- is then check against other website nicknames that may have this url. User is
-- then promted to either use a new url or change nickname to matching url.
websiteLoop :: [PassInfo] -> IO (String, String)
websiteLoop ls = do
    putStr ("Enter a new website name:\n")
    input <- getLine
    case duplicateWeb ls input of
        Just dupURLName -> do
            putStr "Found matching website name.\n"
            putStr $ "Using URL \"" ++ dupURLName ++ "\"\n"
            pure (input, dupURLName)
        otherwise -> urlLoop ls input

-- Asks user for url. Then searches list of passInfo to check for duplicates entries
-- of given website name. The user is then given the option to change their website name
-- to this value or use a new url.
urlLoop :: [PassInfo] -> String -> IO (String, String)
urlLoop masterList websiteName = do
    putStr("Enter a URL:\n")
    newURL <- getLine
    case duplicateURL masterList newURL of
        Just dupWebName -> do
            putStr("Duplicate url found with nickname \"" ++ dupWebName ++ "\"\n")
            putStr("Would you like to use this website name instead?\n")
            yn <- yesNoLoop
            if yn
                then pure (dupWebName, newURL)
                else do
                    putStr "Please enter a new URL.\n"
                    urlLoop masterList websiteName
        otherwise -> pure (websiteName, newURL)

-- Ask user yes or no prompt. Returns true if the answer is yes, false if no.                
yesNoLoop :: IO Bool
yesNoLoop = do
    putStr "Enter y/n:\n"
    input <- getLine
    case map toLower input of
        "y" -> pure True
        "yes" -> pure True
        "n" -> pure False
        "no" -> pure False
        otherwise -> do
            putStr "Unrecognized input. Please try again.\n\n"
            yesNoLoop

handleSearch :: [PassInfo] -> IO ()
handleSearch masterList = do
    putStr ("Do you want to search by:\n")
    putStr ("Userkey|Website|Password\n")
    searchType <- getLine
    case searchType of
        "Userkey" -> do
            infoLs <- searchUsernames masterList
            if null infoLs
                then do
                    putStr "No matches found.\n"
                    handleLoop masterList
                else do
                    putStr ("\nInfo that uses that Userkey:\n")
                    printOrderedList infoLs
                    num <- choiceLoop $ length infoLs
                    
                    let specificPassInfo = infoLs !! (num-1)

                    optionLoop specificPassInfo masterList
        "Website" -> do
            putStr ("Enter a website:\n")
            line <- getLine
            let infoLs = fetchFromWebsite line masterList
            if null infoLs
                then do
                    putStr "No matches found.\n"
                    handleLoop masterList
                else do
                    putStr ("\nInfo that uses that website:\n")
                    printOrderedList infoLs
                    num <- choiceLoop $ length infoLs

                    let specificPassInfo = infoLs !! (num-1)

                    optionLoop specificPassInfo masterList
        "Password" -> do
            putStr ("Enter a password:\n")
            line <- getLine
            let infoLs = fetchFromPassword line masterList
            if null infoLs
                then do
                    putStr "No matches found.\n"
                    handleLoop masterList
                else do
                    putStr ("\nInfo that uses that password:\n")
                    printOrderedList infoLs
                    num <- choiceLoop $ length infoLs

                    let specificPassInfo = infoLs !! (num-1)
                    
                    optionLoop specificPassInfo masterList
        dfault -> do
            putStr "Incorrect option. Please try again.\n\n"
            handleSearch masterList
    where
        choiceLoop :: Int -> IO Int
        choiceLoop max = do
            putStr ("\nEnter an item number:\n")
            numberToPick <- getLine
            let num = read numberToPick :: Int
            if (num > max) || (num < 1)
                then do
                    putStr "Invalid index.\n"
                    choiceLoop max
                else
                    pure num
        optionLoop :: PassInfo -> [PassInfo] -> IO ()
        optionLoop specificPassInfo masterList = do
                    putStr "Account information:"
                    putStr (showFull specificPassInfo)
                    putStr ("Do you want to Delete|Edit|CopyPassword|Return\n")
                    option <- getLine

                    case option of
                        "Delete" -> do
                            handleLoop (filter (/= specificPassInfo) masterList)
                        "Edit" -> do
                            let rmList = filter (/= specificPassInfo) masterList
                            newInfo <- (handleEdit rmList specificPassInfo)
                            let newList = newInfo : rmList
                            optionLoop newInfo newList
                        "CopyPassword" -> do
                            setClipboard $ password specificPassInfo
                            putStr "Password has been copied to clipboard.\n"
                            putStr "Press enter to continue.\n"
                            hSetBuffering stdin NoBuffering
                            hSetEcho stdin False
                            x <- getChar
                            hSetBuffering stdin LineBuffering
                            hSetEcho stdin True
                            putStr "Password cleared from clipboard.\n"
                            setClipboard ""
                            optionLoop specificPassInfo masterList
                        "Return" -> do
                            handleLoop masterList
                        otherwise -> do
                            putStr "Incorrect option. Please try again.\n\n"
                            optionLoop specificPassInfo masterList

searchUsernames :: [PassInfo] -> IO [PassInfo]
searchUsernames ls = do
    putStr("Do you want to search by 'Username', 'Email', or 'Phonenumber'?\n")
    usernameType <- getLine
    case usernameType of
        "Username" -> do
            putStr("Enter the username:\n")
            input <- getLine
            pure $ go isUsername input ls
        "Email" -> do
            putStr("Enter the email:\n")
            input <- getLine
            pure $ go isEmail input ls
        "Phonenumber" -> do
            putStr("Enter the phone number:\n")
            input <- getLine
            pure $ go isPhone input ls
        otherwise -> do
            putStr "Incorrect option. Please try again.\n"
            searchUsernames ls
    where
        go :: (UsernameData -> Bool) -> String -> [PassInfo] -> [PassInfo]
        go pred str ls = filter ((any (\x -> (pred x) && ((getUsernameDataStr x) == str))) . username) ls


handleEdit :: [PassInfo] -> PassInfo -> IO PassInfo
handleEdit ls (PassInfo username password website url) = do
    putStr ("Do you want to change the Userkeys|Password|Website|Done\n")
    toChange <- getLine
    case toChange of
        "Userkeys" -> do
            newusernames <- (editUsernamesFromUser username)
            handleEdit ls (PassInfo newusernames password website url)
        "Password" -> do
            input <- addPasswordLoop ls
            handleEdit ls (PassInfo username input website url)
        "Website" -> do
            (websiteName, urlName) <- websiteLoop ls
            handleEdit ls (PassInfo username password websiteName urlName)
        "Done" -> return (PassInfo username password website url)
        otherwise -> do
            putStr "Incorrect option. Please try again.\n\n"
            handleEdit ls (PassInfo username password website url)

-- Gets a list of UsernameData from the user
getUsernamesFromUser :: [UsernameData] -> IO [UsernameData]
getUsernamesFromUser acc = if null outputOptions 
    then pure acc
    else do
        putStr("Do you want to add a " ++ (go outputOptions) ++ ".\n")
        putStr("Type 'Done' to stop.\n")
        newUsernameType <- getLine
        case newUsernameType of
            "Done" -> return acc
            "Username" -> 
                if isAnyUser
                    then do
                        putStr "Incorrect option. Please try again.\n"
                        getUsernamesFromUser acc
                    else do
                        putStr("Enter a username:\n")
                        newUsername <- getLine
                        getUsernamesFromUser ((Username newUsername) : acc)
            "Email" -> 
                if isAnyEmail
                    then do
                        putStr "Incorrect option. Please try again.\n"
                        getUsernamesFromUser acc
                    else do
                        putStr("Enter an email:\n")
                        newUsername <- getLine
                        getUsernamesFromUser ((Email newUsername) : acc)
            "Phonenumber" -> 
                if isAnyPhone
                    then do
                        putStr "Incorrect option. Please try again.\n"
                        getUsernamesFromUser acc
                    else do
                        putStr("Enter a phonenumber:\n")
                        newUsername <- getLine
                        getUsernamesFromUser ((PhoneNumber newUsername) : acc)
            dfault -> do
                putStr "Incorrect option. Please try again.\n"
                getUsernamesFromUser acc
    where
        isAnyUser = any isUsername acc
        isAnyPhone = any isPhone acc
        isAnyEmail = any isEmail acc
        ls1 = if not isAnyPhone then ["'Phonenumber'"] else []
        ls2 = if not isAnyEmail then "'Email'" : ls1 else ls1
        outputOptions = if not isAnyUser then "'Username'" : ls2 else ls2
        go :: [String] -> String
        go [x] = x
        go [x,y] =  x ++ ", or " ++ y
        go (x:xs) = x ++ ", " ++ (go xs)
        go [] = ""

-- Edit a list of UsernameData from the user
editUsernamesFromUser :: [UsernameData] -> IO [UsernameData]
editUsernamesFromUser acc = do
    putStr("Do you want to edit a 'Username', 'Email', or 'Phonenumber'.\n")
    putStr("Type 'Done' to stop.\n")
    newUsernameType <- getLine
    case newUsernameType of
        "Done" -> return acc
        "Username" -> do
            let newList = filter (not . isUsername) acc
            putStr("Enter the username.\n")
            newUsername <- getLine
            editUsernamesFromUser ((Username newUsername) : newList)
        "Email" -> do
            let newList = filter (not . isEmail) acc
            putStr("Enter the email.\n")
            newUsername <- getLine
            editUsernamesFromUser ((Email newUsername) : newList)
        "Phonenumber" -> do
            let newList = filter (not . isPhone) acc
            putStr("Enter the phonenumber.\n")
            newUsername <- getLine
            editUsernamesFromUser ((PhoneNumber newUsername) : newList)
        dfault -> do
            putStr "Incorrect option. Please try again.\n"
            editUsernamesFromUser acc

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

fetchFromWebsite :: String -> [PassInfo] -> [PassInfo]
fetchFromWebsite searchFor [] = []
fetchFromWebsite searchFor ((PassInfo usernames password website url):xs) = 
        if (searchFor == website)
        then (PassInfo usernames password website url) : (fetchFromWebsite searchFor xs)
        else (fetchFromWebsite searchFor xs)

fetchFromPassword :: String -> [PassInfo] -> [PassInfo]
fetchFromPassword searchFor [] = []
fetchFromPassword searchFor ((PassInfo usernames password website url):xs) = 
        if (searchFor == password)
        then (PassInfo usernames password website url) : (fetchFromPassword searchFor xs)
        else (fetchFromPassword searchFor xs)

printOrderedList :: (Show a) => [a] -> IO ()
printOrderedList ls = do
    mapM_ putStr $ zipWith (++) (map (\x -> "Item " ++ (show x) ++ ":\n") [1..(length ls)]) $ map show ls

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

-- Returns true is there is duplicate PassInfo in a list, excluding the password.
duplicateInfo :: [PassInfo] -> PassInfo -> Bool
duplicateInfo [] _ = False
duplicateInfo ((PassInfo {username = userLs, website = webLs, url = urlLs}):xs) pi@PassInfo{username = userI, website = webI, url = urlI} =
    if (matchingElement userLs userI) && (webLs == webI) && (urlLs == urlI)
        then True
        else duplicateInfo xs pi

-- Checks if two list have at least one matching element
matchingElement :: (Eq a) => [a] -> [a] -> Bool
matchingElement ls1 ls2 = any pred ls1
    where
        pred user = elem user ls2

-- Returns the number of PassInfo's that have the same password
numDuplicatePass :: [PassInfo] -> String -> Int
numDuplicatePass ls pass = length $ filter (\x -> pass == (password x)) ls

-- Given a url, if a duplicate url is found, returns Just of the website name. 
-- Otherwise returns Nothing
duplicateURL :: [PassInfo] -> String -> Maybe String
duplicateURL ls urlName = let
    mUrlLs = dropWhile (\x -> (url x) /= urlName) ls
    in if null mUrlLs
        then Nothing
        else Just $ website $ head mUrlLs

-- Given a website name, searches for duplicate website name.
-- If duplicate is found returns may of the matching url. Otherwise return Nothing
duplicateWeb :: [PassInfo] -> String -> Maybe String
duplicateWeb ls websiteName = let
    matchWeb = dropWhile (\x -> (website x) /= websiteName) ls
    in if null matchWeb
        then Nothing
        else Just $ url $ head matchWeb

dropDuplicateInfo :: [PassInfo] -> [PassInfo]
dropDuplicateInfo [] = []
dropDuplicateInfo (x:xs) =
    if (elem x xs)
        then dropDuplicateInfo xs
        else x : dropDuplicateInfo xs

-- Converts a string to an integer value.
-- takes the string and 0 as an input.
getPasswordStrength :: String -> PasswordStrength
getPasswordStrength pass = 
    if (passwordNumber >= 40)
        then Strong
        else if (passwordNumber >= 25)
            then Medium
            else if (passwordNumber >= 10)
                then Weak
                else VeryWeak
    where
        hasSpecialCharMult = if any (\x -> elem x "!@#$%^&*()_-~`+=<>?:{}|,./\\;\'[]\"") pass
            then 2.0
            else 1.0
        hasNumberMult = if any (\x -> elem x "0123456789") pass
            then 1.5
            else 1.0
        hasUpperAndLowerMult = if (map toLower pass) /= pass
            then 2.0
            else 1.0
        passwordNumber :: Double
        passwordNumber = hasSpecialCharMult * hasNumberMult * hasUpperAndLowerMult * (fromIntegral (length pass))

-- Exports a list of PassInfo to a file.
-- takes a file path and list of PassInfo.
exportPasswordInfo :: String -> [PassInfo] -> IO()
exportPasswordInfo path xs = writeFile path (listToString xs "")

-- Exports a list of PassInfo to an encrypted file.
-- takes a list of PassInfo.
exportEncPasswordInfo :: FilePath -> FilePath -> [PassInfo] -> IO ()
exportEncPasswordInfo pathBin pathData xs = do
    writeFile "tempExport.txt" (listToString xs "")
    binData <- readBin "resources\\data.bin"
    key <- passwordLoop binData
    encryptFile "tempExport.txt" pathData key
    writeBin pathBin (binSalt binData) (binPassHash binData)
    removeFile "tempExport.txt"

importEncPasswordInfo :: FilePath -> FilePath -> IO Bool
importEncPasswordInfo pathBin pathData = do
    dfeBin <- doesFileExist pathBin
    dfeData <- doesFileExist pathData
    if not dfeBin
        then do
            putStr "Cannot find .bin file.\n"
            pure False
        else if not dfeData
            then do
                putStr "Cannot find .dat file.\n"
                pure False
            else do
                fileSize <- getFileSize pathBin
                if fileSize /= 48
                    then do
                        putStr "Bin file has incorrect format. Check that file used is correct.\n"
                        pure False
                    else do
                        binData <- readBin pathBin
                        key <- passwordLoop binData
                        decryptFile pathData "tempImport.txt" key
                        pure True

-- Converts a list of PassInfo to an exportable string.
-- takes a list of PassInfo and an empty list as input.
listToString :: [PassInfo] -> String -> String
listToString [] acc = acc
listToString (x:xs) acc = 
    acc ++ (passInfoToString x) ++ "\n" ++ (listToString xs acc)


-- Returns true if given UsernameData is an instance of Username
isUsername :: UsernameData -> Bool
isUsername (Username _) = True
isUsername _ = False

-- Returns true if given UsernameData is an instance of Email
isEmail :: UsernameData -> Bool
isEmail (Email _) = True
isEmail _ = False

-- Returns true if given UsernameData is an instance of PhoneNumber
isPhone :: UsernameData -> Bool
isPhone (PhoneNumber _) = True
isPhone _ = False
