
import sys



def print_modulus_array(modulus_array: list[str]):
    res = "unsigned char prov_key_be_modulus[] = {"
    arr = []
    for b in modulus_array[1:]:
        arr += ["0x" + b]
    s = ", ".join(arr)
    return res + s + "};"
    #print ("Length of modulus_array " + str(len(modulus_array[1:])))

def print_exponent_array(ex: str):
    res = "unsigned char prov_key_be_exponent[] = { "
    e = int(ex)
    be_bytes = e.to_bytes(4, 'big')
    arr = []
    for b in be_bytes:
        arr += ["0x%02x" % b]
    s = ", ".join(arr)
    return res + s + "};"

def main():
    fname = sys.argv[1]
    with open(fname) as f:
        lines = f.readlines()
        modulus_idx = -1
        exponent_idx = -1
        for idx, line in enumerate(lines):
            if line.startswith('modulus'):
                modulus_idx = idx
            if line.startswith('publicExponent'):
                exponent_idx = idx

        modulus = ""
        for line in lines[modulus_idx+1:exponent_idx]:
            line = line.strip()
            modulus += line
        
        exponent_line = lines[exponent_idx]
        exponent = exponent_line.split(' ')[1]
        
        print (print_modulus_array(modulus.split(':')) + print_exponent_array(exponent))

if __name__ == '__main__':
    main()
