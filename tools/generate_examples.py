"""Generate documented input bytes, independent oracles and three example configs."""
import base64
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def save(path,value):
    path=ROOT/path; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value,indent=2)+'\n')
def oracle(target,name,code,out,err=b''):
    value={'schema_version':'1.0','provenance':{'source':f'oracles/{target}/SPEC.md#{name}','independent':True},'exit_code':code,
           'stdout':{'mode':'exact','base64':base64.b64encode(out).decode()},'stderr':{'mode':'exact','base64':base64.b64encode(err).decode()}}
    save(Path('oracles')/target/(name+'.json'),value)

def generate():
    cases={'bytecount': [('binary','valid',b'abc\0\xff','accepted'),('empty','boundary',b'','accepted'),('invalid','invalid',b'!bad','invalid'),('marker','original',b'padding-MARK-tail','accepted')],
           'lineparse':[('seven','valid',b'7','seven'),('plus','valid',b'+7','seven'),('low','boundary',b'-100','boundary'),('invalid','invalid',b'bad','invalid')]}
    oracle('bytecount','accepted',0,b'OK\n');oracle('bytecount','invalid',2,b'',b'invalid\n')
    oracle('lineparse','seven',0,b'49\n');oracle('lineparse','boundary',0,b'10000\n');oracle('lineparse','invalid',2,b'',b'invalid\n')
    for target,tests in cases.items():
        for name,category,data,expected in tests:
            path=ROOT/'corpus'/target/'inputs'/(name+'.bin');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    for target,mode in [('bytecount','stdin'),('bytecount','file'),('lineparse','argv')]:
        compiler='gcc' if target=='bytecount' else 'g++'
        filename='main.c' if target=='bytecount' else 'main.cpp'
        base_flags=['-Wall','-Wextra','-fstack-protector-strong','-fPIE','-pie','-Wl,-z,relro,-z,now']
        builds={kind:{'compiler':compiler,'flags':base_flags+flags,'command':['{compiler}','{flags}',filename,'-o','program'],'binary':'program'}
                for kind,flags in [('release',['-O2']),('sanitized',['-O1','-g','-fno-omit-frame-pointer','-fsanitize=address,undefined'])]}
        config={'schema_version':'1.0','target':target,'fixture':True,'source':{'repo':f'../.fixture-repos/{target}','base':'base','candidate':'candidate'},
                'builds':builds,'input':{'mode':mode,'argv':['{binary}',mode]+(['{input}'] if mode!='stdin' else []),'cwd':'.'},
                'environment':{'image':'patchcheck-framework:1.0','variables':{'ASAN_OPTIONS':'detect_leaks=0:abort_on_error=1:symbolize=1','UBSAN_OPTIONS':'print_stacktrace=1:halt_on_error=1'}},
                'tools':{'gcc':r'gcc .*','g++':r'g\+\+ .*','readelf':r'GNU readelf .*','git':r'git version .*','python3':r'Python 3\..*'},
                'limits':{'wall_seconds':3,'cpu_seconds':2,'memory_mb':384,'pids':32,'output_bytes':1048576,'file_bytes':16777216,'build_wall_seconds':90},
                'tests':[],'corpus_dir':f'../corpus/{target}/regressions','analyzers':['unknown']+(['fixture-marker'] if target=='bytecount' else []),
                'minimization':{'max_attempts':100,'wall_seconds':180}}
        for name,category,data,expected in cases[target]:
            config['tests'].append({'id':name,'category':category,'input':f'../corpus/{target}/inputs/{name}.bin','oracle':f'../oracles/{target}/{expected}.json',
                                    'signature':{'error_type':'fixture-marker','location':'marker-check','key':'MARK'} if name=='marker' else None})
        save(Path('configs')/(target+'-'+mode+'.json'),config)
if __name__=='__main__':generate()
