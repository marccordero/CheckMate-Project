#!/usr/bin/python3

def main():
    badchar = "\\x00"
    user = input("Filename: ")
    file = open(user, "r+")
    lines = file.readlines()

    for line in lines: 
        if (badchar in line):
            output = line.replace(badchar, "")
        
            file.write(output)

        elif not badchar in line:
            file.write(line)

if __name__ == "__main__":
    main()