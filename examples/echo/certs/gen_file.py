
if __name__ == '__main__':
#  n = 9999
  n = 65535 # FFFF
  with open("bb.txt", "w") as file1:
      # Writing data to a file
      for i in range(n,  0, -1 ):
        #file1.write( "{:04}".format(i)+'\n' )
        file1.write( "{:04X}".format(i)+'\n')


