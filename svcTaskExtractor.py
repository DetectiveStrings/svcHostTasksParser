import sys 
from numpy import array
import os , csv

ALF = 'ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-*/+/.,\'\\][":?><+_=-0987654321~!@#$%^&*()];l\n\t'

def Usage():
    print("svcTaskExtractor.py <svchost.dmp>")

def isTaskStart(poss , svcdump ):
    newTaskPoss = svcdump[poss:].find(bytearray([0x4e , 0x00 , 0x54 , 0x00 , 0x20 , 0x00 , 0x54 , 0x00 , 0x41 ,0x00 , 0x53 , 0x00 , 0x4b , 0x00 , 0x5c , 0x00 ]))
    return poss+newTaskPoss

def isTaskEnd(poss , nextposs , svcdump ):
    endcheck = svcdump[poss:nextposs].find(bytearray([ 0xd8 , 0x01 , 0x00  ]))
    
    if(endcheck > 0 ) :
        
        while endcheck > 0 : 
            endcheck += 4
            poss += endcheck
            endcheck = svcdump[poss:nextposs].find(bytearray([ 0xd8 , 0x01 , 0x00  ]))
            

    return(poss)


def Getoff(svcdump , taskStart , taskEnd):
    i = taskStart
    sss = []
    while i < taskEnd : 
        if svcdump[i] != 0 :
            if(svcdump[i+1] != 0 and svcdump[i+2] != 0):
                while svcdump[i] != 0  or svcdump[i+1] != 0 :
                    sss.append(hex(int(svcdump[i])))
                    i += 1 
                return sss[-3 : ]
        i += 1

def checksss(Gsss , sss):
    if(Gsss ==sss):
        return 1 
    else : 
        return 0 

def dubeCheck(svcdump , taskStart , taskEnd , Gsss):
    intGss = [int(x,16) for x in Gsss]
  #  print(bytearray(intGss))
    ch = (svcdump[taskStart:taskEnd]).find(bytearray(intGss))
    return(ch)

        
def writetocsv(outputfolder , data = [] , header = [] ):
    if(header):
        with open(outputfolder+'/dump.csv', 'w', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            f.close()
    if(data):
        with open(outputfolder+'/dump.csv', 'a' , newline='' ) as f:
            writer = csv.writer(f)
            print(data)
            writer.writerow(data)
            f.close()

def pareNTname(svcdump , taskStart , taskEnd):
    for xx in range( taskStart , taskEnd):
        if(svcdump[xx] == 0 and svcdump[xx+1] == 0 ):
            return (svcdump[taskStart:xx].decode('utf-8')) , xx 


def pares(svcdump , taskStart , taskEnd):
    taskname , stop1 = pareNTname(svcdump , taskStart , taskEnd)
    sss = Getoff(svcdump , stop1 , taskEnd)
  #  print(sss)
    return taskname , sss , stop1 

def GetClearData(svcdump , Gsss) :
    datalist = [] 
    
    dataloc = 1
    holder = -1 
    while  dataloc > 0 : 
        dataholder = ""
        holder += dataloc
        dataloc = svcdump[holder:].find(bytearray([int(x,16) for x in Gsss]))
        for i in range (holder , holder+dataloc) :
            
            if( chr(svcdump[i]) in ALF ):
                dataholder += chr(svcdump[i]) 
                
        print(dataholder)
        datalist.append(dataholder)
        dataloc += 1
    return datalist 




try : 
    svcdump = open(sys.argv[1], 'rb').read()
    svcdumplen = len(svcdump)
    print(hex(svcdumplen))
    i = 0 
    sssFlag = 0 
    Gsss = [] 
    taskposs = isTaskStart(i , svcdump)
    i = taskposs + 1 
    dir = sys.argv[1].replace('.' , '')+"Output"
    isExist = os.path.exists(dir)
    if( not isExist):
        os.mkdir(dir)

    writetocsv(dir ,[] , ['offset' , 'TaskName' , 'TaskObjectLen' , 'aboutTaskEnd' , 'aboutTaskSize' , 'IsMagicfound' , 'MagicCheck' , "MagicDoubleCheck" ]  )

    datahub = []
    while  i < (svcdumplen):
        data = [] 
        valedTaskpr = ''
        i = isTaskStart(i , svcdump)

        if(i == taskposs):
            break
        
        taskend = isTaskEnd(taskposs, i , svcdump)
        data.append(str(hex(taskposs)))

        task = '' 

        if(taskposs != taskend ):  
            task , SHsss , stop1 = pares(svcdump , taskposs , taskend )
            leen = taskend - taskposs
            valedTaskpr += '1' 
        else : 
            task , SHsss , stop1 = pares(svcdump , taskposs , i )
            leen = i - taskposs
            valedTaskpr += '0' 
        #print(str(taskposs) +'\t | \t '+ task + '\t | \t ' + taskmess ) 
        data.append(str(task).replace('\x00' , ''))
        data.append(str(hex(leen)))
        if(leen < 0x10000): 
            valedTaskpr += '1'
        else : 
            valedTaskpr += '0'  

        if( (not sssFlag) and valedTaskpr ):
            Gsss = SHsss[1:]
            sssFlag = 1
         #   print(Gsss)
            valedTaskpr += '111' 
        else : 
            if(SHsss):
                valedTaskpr += '1'
                res = checksss(Gsss , SHsss[1:])
                if(res):
                    #print("Valed Task")
                    valedTaskpr += '11' 
                else : 
                    valedTaskpr += '0'
                    if( dubeCheck(svcdump,taskposs , taskposs+leen , Gsss) > 0 ) : 
                      #  print('we can try to extract data ')
                        valedTaskpr += '1'
                    else : 
                         valedTaskpr += '0'

            else : 
              #  print ("not valed task object")
                valedTaskpr += '000' 


       # if(valedTaskpr[-1:] )
        if(valedTaskpr[0] == '0' ):
            data.append('object end bytes not found , which means the task object may be destroyed')
        else : 
            data.append( '' )

        if(valedTaskpr[1] == '0' ):
            data.append('the task object is too large , i think we may be in the task object grave')
        else : 
            data.append( '' )

        if (valedTaskpr[2] == '0'):
            data.append('object magic descriptor is totally not found , i can\'to extract anything from here , it will be time waste ')
        else :
            data.append( '' )

        if(valedTaskpr[3] == '0'): 
            data.append( 'object global magic descriptor is not found , i will try to double check ' )
        else : 
            data.append("")

        if(valedTaskpr[4]== '0'):
            data.append( 'object global magic descriptor is not found, ican\'t do anything for this one')



        if(valedTaskpr[-1:] != '0'):
            dumpdata = GetClearData(svcdump[stop1:taskposs+leen], Gsss)
    #        print(data)



        writetocsv(dir ,data )
        with open("dmp/"+data[0]+'.La' , 'w') as wr : 
            for dm in dumpdata : 
                wr.write(dm)
                wr.write('\n')
            wr.close()
        datahub.append(data)
        taskposs = i 
        i += 1


        if not (i%0x1000000):
            print(hex(i))






except : 
    Usage()
