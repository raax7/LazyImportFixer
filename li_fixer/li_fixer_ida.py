
import idaapi
import ida_kernwin

def RenameFunctions(FilePath):
    with open(FilePath, 'r') as file:
        # Check if the first line is equal to the magic number
        MagicNumber = file.readline().strip()
        if MagicNumber != "li_fixer":
            ida_kernwin.error("The file is not a valid li_fixer output.")
            return

        for line in file:
            FunctionName, Address = line.strip().split(',')
            Address = int(Address, 16)
            Address += idaapi.get_imagebase()
            idaapi.set_name(Address, FunctionName)
            print(f"Renamed function at 0x{Address:08X} to {FunctionName}")

FilePath = ida_kernwin.ask_file(0, "*.txt", "Please select the functions file that li_fixer generated.")
if FilePath:
    RenameFunctions(FilePath)
else:
    ida_kernwin.error("No file selected.")
