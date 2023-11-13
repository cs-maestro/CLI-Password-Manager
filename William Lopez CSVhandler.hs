module Main where
import Data.List.Split

-- A csv can be turned into a values split into lists.
type LSV = [[String]]

main :: IO ()
main = do
    csv <- readFile "resources\\info.txt"
    let lsv = lsvFromCsv csv
    handleLoop lsv

handleLoop :: LSV -> IO ()
handleLoop lsv = do
    putStr "\nEnter a Command\n"
    putStr "All|Add|Delete|Get|Export|Quit\n"
    nextCommand <- getLine
    if (nextCommand == "Quit")
        then putStr "Goodbye\n"
        else case nextCommand of
            "All" -> do
                printFormated lsv
                handleLoop lsv
            "Add" -> do 
                putStr "Please enter values separated by commas:\n"
                putStr "Format: (website),(URL),(username),(password), ... (Additional Keywords)\n"
                toAdd <- getLine
                export "resources\\info.txt" (lsv ++ (lsvFromCsv toAdd))
                handleLoop (lsv ++ (lsvFromCsv toAdd))
            "Delete" -> do
                putStr "Please enter a website, username, password, and all addition keywords:\n"
                putStr "Format: (website),(URL),(username),(password), ... (Additional Keywords)\n"
                key <- getLine
                export "resources\\info.txt" (deleteFromLSV ((splitOn ",") key) lsv)
                handleLoop (deleteFromLSV ((splitOn ",") key) lsv)
            "Get" -> do 
                putStr "Enter a keyword:\n"
                key <- getLine
                printFormated (fetchByKeywords ((splitOn ",") key) lsv)
                handleLoop lsv
            "Export" -> do
                putStr "Enter a file path:\n"
                exportPath <- getLine
                export exportPath lsv
                handleLoop lsv
            dfault -> do
                putStr "Command not recognized.\n"
                handleLoop lsv

printFormated :: LSV -> IO ()
printFormated [] = putStr "\n"
printFormated (list:xs) = do
    putStr ("\nWebsite: " ++ (head list))
    putStr ("\nURL: " ++ (list!!1))
    putStr ("\nUsername: " ++ (list!!2))
    putStr ("\nPassword: " ++ (list!!3))
    putStr ("\nAll Keywords: " ++ (show list) ++ "\n")
    printFormated xs

-- Removes a sublist from an lsv. Requires the full info info of that sublist.
deleteFromLSV :: [String] -> LSV -> LSV
deleteFromLSV [] xs = []
deleteFromLSV words [] = []
deleteFromLSV words xs = filter (/= words) xs

-- Gets a sublist which contains the desired keywords.
-- Returns only sublists that contains all keywords.
fetchByKeywords :: [String] -> LSV -> LSV
fetchByKeywords keywords [] = []
fetchByKeywords [] xs = []
fetchByKeywords keywords xs = filter (containsAll keywords) xs
    where
        containsAll :: Eq a => [a] -> [a] -> Bool
        containsAll [] xs = True
        containsAll keywords [] = False
        containsAll (k:keywords) xs =
            if (elem k xs)
                then containsAll keywords xs
                else False


-- Turns a csv string into a list of lists of strings.
lsvFromCsv :: String -> LSV
lsvFromCsv csv = (map (filter (/= "")) (map (splitOn ",") (lines csv)))

-- Turns a list of lists of strings into a csv file
-- Where sublists are lines.
csvFromLsv :: LSV -> String
csvFromLsv [] = []
csvFromLsv (x:xs) = (go x) ++ "\n" ++ (csvFromLsv xs)
    where
        go :: [String] -> String
        go [] = []
        go (f:s) = f ++ "," ++ (go s)

--Exports a lsv to a csv file.
export :: String -> LSV -> IO ()
export path xs = writeFile path (csvFromLsv xs)