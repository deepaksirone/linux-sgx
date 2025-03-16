
import sys



def print_modulus_array(name: str, modulus_array: list[str]):
    res = "unsigned char " + name + "[] = {"
    arr = []
    for b in modulus_array[1:]:
        arr += ["0x" + b]
    s = ", ".join(arr)
    return res + s + "};"
    #print ("Length of modulus_array " + str(len(modulus_array[1:])))

def print_exponent_array(name: str, ex: str):
    res = "unsigned char " + name + "[] = { "
    e = int(ex)
    be_bytes = e.to_bytes(4, 'big')
    arr = []
    for b in be_bytes:
        arr += ["0x%02x" % b]
    s = ", ".join(arr)
    return res + s + "};"

def print_private_exponent_array(name: str, pvt_ex: list[str]):
    res = "unsigned char " + name + "[] = { "
    arr = []
    for b in pvt_ex:
        arr += ["0x" + b]
    s = ", ".join(arr)
    return res + s + "};"

def main():
    fname = sys.argv[1]
    with open(fname) as f:
        lines = f.readlines()
        modulus_idx = -1
        exponent_idx = -1
        pvt_exponent_idx = -1
        prime1_idx = -1
        for idx, line in enumerate(lines):
            if line.startswith('modulus'):
                modulus_idx = idx
            if line.startswith('publicExponent'):
                exponent_idx = idx
            if line.startswith('privateExponent'):
                pvt_exponent_idx = idx
            if line.startswith('prime1'):
                prime1_idx = idx

        modulus = ""
        for line in lines[modulus_idx+1:exponent_idx]:
            line = line.strip()
            modulus += line

        pvt_exponent = ""
        for line in lines[pvt_exponent_idx + 1:prime1_idx]:
            line = line.strip()
            pvt_exponent += line
        
        exponent_line = lines[exponent_idx]
        exponent = exponent_line.split(' ')[1]
        
        print (print_modulus_array("prov_key_be_modulus", modulus.split(':')) + print_exponent_array("prov_key_be_exponent", exponent) + print_private_exponent_array("prov_key_be_pvt_exponent", pvt_exponent.split(':')))
        #print (len(pvt_exponent.split(':')))

if __name__ == '__main__':
    main()
