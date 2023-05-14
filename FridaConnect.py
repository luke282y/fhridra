import frida
import os
from typing import Any, Mapping, Tuple, Union

class Connector:
    def __init__(self,ip_address,process_name,script_folder):
        self.ip_address = ip_address
        self.process_name = process_name
        self.script_folder = script_folder
        self.device = None
        self._connect()
        self._load_core()
        self._load_user_modules()
        self.image_base = self.getBase()

    def _connect(self):
        dm = frida.get_device_manager()
        self.device = dm.add_remote_device(self.ip_address)
        self.session = self.device.attach(self.process_name)

    def _load_core(self):
        script = """ \
        rpc.exports = {
            eval: function (expression) {
                //console.log(expression)
                return evaluate(() => (1, eval)(expression));
            }
        };

        function evaluate(func) {
            try {
                const result = func();
                if (result instanceof ArrayBuffer) {
                    return result;
                } else {
                    const type = (result === null) ? 'null' : typeof result;
                    return [type, result];
                }
            } catch (e) {
                return ['error', {
                    name: e.name,
                    message: e.message,
                    stack: e.stack
                }];
            }
        }
        """
        script=self.session.create_script(script)
        script.load()
        api = script.exports_sync 
        setattr(self,"core",api)

    def _load_user_modules(self):
        for file in os.listdir(self.script_folder):
            path = os.path.join(self.script_folder,file)
            if(not os.path.isfile(path)):
                continue
            name,ext = os.path.splitext(file)
            if(ext!=".js"):
                continue
            with open(path,"r") as fin:
                script = fin.read()
            script=self.session.create_script(script)
            script.load()
            api = script.exports_sync 
            setattr(self,name,api)
            print(f"Loaded Module: {name}")         
            print(dir(api))
    
    def _parse_evaluate_result(self, result: Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]) -> Tuple[str, bytes]:
        if isinstance(result, bytes):
            return ("binary", result)
        elif isinstance(result, dict):
            return ("binary", bytes())
        elif result[0] == "error":
            raise JavaScriptError(result[1])
        return (result[0], result[1])
    
    def eval(self,expression):
        result = self.core.eval(expression)
        result = self._parse_evaluate_result(result)
        return result
    
    def getBase(self):
        base = self.eval(
            f"Module.getBaseAddress('{self.process_name}')"
        )[1]
        base = int(base,16)
        return base

    def curAddr(self):
        return fridaPointer(self,currentAddress.getOffset())

    def rebase(self,base):
        currentProgram.setImageBase(toAddr(base),True)

    def hook(self,addr=None):
        
        if(addr==None):
            fp = self.curAddr()
        else:
            fp = fridaPointer(self,addr)

        expression = r'''
                    function trydump(data){
                        try{
                            console.log(hexdump(data,{length:0x40}))
                        }catch(error){}
                    }
                    '''
        expression += f"var hook = Interceptor.attach({fp.addr}"
        expression += r'''
                    , {
                        onEnter(args) {
                    '''
        expression += f"console.log(DebugSymbol.fromAddress({fp.addr}))"
        expression += r'''
                        console.log("arg1: "+args[0])
                        trydump(args[0])
                        console.log("arg2: "+args[1])
                        trydump(args[1])
                        console.log("arg3: "+args[2])
                        trydump(args[2])
                        console.log("arg4: "+args[3])
                        trydump(args[3])
                        console.log(JSON.stringify(this.context,null,2))
                        console.log('Backtrace:\n' +
                            Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n') + '\n');
                        }
                    });
                    '''
        print(expression)
        print(self.eval(expression))

class JavaScriptError(Exception):
    def __init__(self, error) -> None:
        super().__init__(error["message"])
        self.error = error

class fridaPointer:
    def __init__(self,connector, addr):
        self.value = addr
        self.addr = f"ptr(0x{addr:x})"
        self.eval = connector.eval
   
    def readCString(self):
        return self.eval(f"{self.addr}.readCString()")[1]
    
    def readPointer(self):
        return self.eval(f"{self.addr}.readPointer()")[1]

    def readS8(self):
        return self.eval(f"{self.addr}.readS8()")[1]
   
    def readU8(self):
        return self.eval(f"{self.addr}.readU8()")[1]

    def readS16(self):
        return self.eval(f"{self.addr}.readS16()")[1]

    def readU16(self):
        return self.eval(f"{self.addr}.readU16()")[1]
    
    def readS32(self):
        return self.eval(f"{self.addr}.readS32()")[1]
    
    def readU32(self):
        return self.eval(f"{self.addr}.readU32()")[1]
    
    def readShort(self):
        return self.eval(f"{self.addr}.readShort()")[1]
    
    def readUShort(self):
        return self.eval(f"{self.addr}.readUShort()")[1]
    
    def readInt(self):
        return self.eval(f"{self.addr}.readInt()")[1]
    
    def readUInt(self):
        return self.eval(f"{self.addr}.readUInt()")[1]
    
    def readFloat(self):
        return self.eval(f"{self.addr}.readFloat()")[1]
    
    def readDouble(self):
        return self.eval(f"{self.addr}.readDouble()")[1]
    
    def readByteArray(self,length,hex=False):
        if(hex):
            return self.eval(f"hexdump({self.addr}.readByteArray({length}))")[1]
        else:
            return self.eval(f"{self.addr}.readByteArray({length})")[1]

if __name__ == "__main__":
    fc = Connector("192.168.122.191","notepad.exe","C:\\frida\\scripts")
    print(fc.session) 
    print(fc.eval("Process"))
    print(hex(fc.image_base))
    fc.rebase(fc.image_base)
    print(hex(fc.curAddr()))
    fp = fridaPointer(fc,fc.curAddr())
    print(fp.readCString())
    print(hex(fp.readInt()))
    print(fp.readByteArray(0x20,hex=True))

