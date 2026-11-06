from pathlib import Path
import subprocess,os,json,time,hashlib,signal,sys,argparse

ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser()
parser.add_argument('--apk',type=Path,default=ROOT.parent/'refurbcheck/dist/RefurbCheck-1.1.0.apk')
parser.add_argument('--no-install',action='store_true',help='Boot and expose command queue before the new APK exists')
parser.add_argument('--duration',type=int,default=7200,help='Keep validation emulator running for this many seconds')
parser.add_argument('--artifacts',type=Path,default=ROOT/'smoke-artifacts-v1.1')
options=parser.parse_args()
SDK=ROOT/'sdk'; APK=options.apk.resolve()
ART=options.artifacts.resolve(); ART.mkdir(exist_ok=True)
QUEUE=ROOT/'smoke-queue'; QUEUE.mkdir(exist_ok=True)
RESULTS=ROOT/'smoke-results'; RESULTS.mkdir(exist_ok=True)
COMPLETED_IDS={p.stem for p in RESULTS.glob('*.json')}
CLAIMED=ROOT/'smoke-claimed'; CLAIMED.mkdir(exist_ok=True)
try:
 INITIAL_LEGACY_ID=json.loads((ROOT/'smoke-command.json').read_text()).get('id')
except (OSError,ValueError):
 INITIAL_LEGACY_ID=None
ENV=os.environ.copy()
ENV['LD_LIBRARY_PATH']=str(ROOT/'emulator-host-libs/usr/lib/x86_64-linux-gnu')+(':'+ENV['LD_LIBRARY_PATH'] if ENV.get('LD_LIBRARY_PATH') else '')
ENV['ANDROID_SDK_ROOT']=str(SDK);ENV['ANDROID_AVD_HOME']=str(ROOT/'avd');ENV['ANDROID_USER_HOME']=str(ROOT/'android-user')
ADB=str(SDK/'platform-tools/adb'); SERIAL='emulator-5580'

def adb(args,timeout=30,binary=False):
 r=subprocess.run([ADB,'-s',SERIAL]+args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if binary:return r.returncode,r.stdout,r.stderr
 return r.returncode,r.stdout.decode('utf-8','replace'),r.stderr.decode('utf-8','replace')

def capture(name):
 result=adb(['exec-out','screencap','-p'],timeout=45,binary=True)
 if result[0]==0:(ART/(name+'.png')).write_bytes(result[1])
 r=adb(['shell','uiautomator','dump','/sdcard/refurbcheck-ui.xml'],timeout=60)
 if r[0]==0:
  r=adb(['exec-out','cat','/sdcard/refurbcheck-ui.xml'],timeout=20)
  (ART/(name+'.xml')).write_text(r[1])
 r=adb(['logcat','-d','-v','threadtime'],timeout=25)
 (ART/(name+'-logcat.txt')).write_text(r[1])
 return {'screenshot':str(ART/(name+'.png')),'ui':str(ART/(name+'.xml'))}

def install_and_launch(name,apk=None):
 apk=Path(apk).resolve() if apk else APK
 print('Installing signed APK',flush=True)
 before=hashlib.sha256(apk.read_bytes()).hexdigest()
 rc,out,err=adb(['install','-r',str(apk)],timeout=180)
 print('Install:',rc,out.strip(),err.strip(),flush=True)
 if rc:raise RuntimeError('APK install failed: '+out+err)
 adb(['logcat','-c'])
 adb(['shell','am','force-stop','io.github.refurbcheck'])
 rc,out,err=adb(['shell','am','start','-W','-n','io.github.refurbcheck/.MainActivity'],timeout=120)
 print('Launch:',rc,out.strip(),err.strip(),flush=True)
 (ART/(name+'-launch.txt')).write_text(out+err)
 if rc or 'Error:' in out:raise RuntimeError('APK launch failed')
 time.sleep(12)
 files=capture(name)
 result={'apk':str(apk),'apk_sha256':before,'api':26,'abi':'x86','kind':'Android emulator; software acceleration; NOT a physical phone','launch_exit':rc,**files}
 (ART/(name+'-result.json')).write_text(json.dumps(result,indent=2))
 print('Smoke capture ready',json.dumps(result),flush=True)
 return result

emu=None
try:
 r=subprocess.run([ADB,'start-server'],env=ENV,capture_output=True,text=True,timeout=20)
 print('ADB server:',r.returncode,(r.stdout+r.stderr).strip(),flush=True)
 log=(ROOT/'emulator-api26.log').open('w')
 command=[str(SDK/'emulator/emulator'),'-avd','RefurbCheck_Smoke','-port','5580','-accel','off','-no-window','-no-audio','-no-snapshot','-no-boot-anim','-gpu','swiftshader_indirect','-feature','-Vulkan','-memory','1536','-cores','2','-no-metrics']
 emu=subprocess.Popen(command,env=ENV,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
 started=time.monotonic();last_print=0;booted=False
 while time.monotonic()-started<600:
  if emu.poll() is not None:raise RuntimeError('Emulator exited: '+str(emu.returncode))
  try:
   rc,out,err=adb(['shell','getprop','sys.boot_completed'],timeout=8)
   if rc==0 and out.strip()=='1':booted=True;break
  except subprocess.TimeoutExpired:pass
  if time.monotonic()-last_print>20:
   print('Waiting for software-emulated Android boot:',round(time.monotonic()-started),'seconds',flush=True);last_print=time.monotonic()
  time.sleep(2)
 if not booted:raise RuntimeError('Software emulator boot timeout (600 seconds)')
 print('Android API26 boot completed in',round(time.monotonic()-started),'seconds',flush=True)
 (ROOT/'emulator-api26-process.json').write_text(json.dumps({'pid':emu.pid,'serial':SERIAL,'log':str(ROOT/'emulator-api26.log'),'driver_pid':os.getpid(),'artifacts':str(ART),'queue':str(QUEUE),'results':str(RESULTS),'booted':True,'api':26,'abi':'x86','started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2))
 adb(['shell','input','keyevent','82'])
 adb(['shell','settings','put','global','window_animation_scale','0'])
 adb(['shell','settings','put','global','transition_animation_scale','0'])
 adb(['shell','settings','put','global','animator_duration_scale','0'])
 if not options.no_install:
  deadline=time.monotonic()+300
  while not APK.exists() and time.monotonic()<deadline:time.sleep(2)
  if not APK.exists():raise RuntimeError('Signed APK did not appear')
  time.sleep(3)
  install_and_launch('initial')
 print('Ready for queued commands; emulator remains live for',options.duration,'seconds',flush=True)
 last_id=INITIAL_LEGACY_ID;deadline=time.monotonic()+options.duration;finish=False
 while time.monotonic()<deadline:
  commands=list(sorted(QUEUE.glob('*.json')))
  cmdfile=ROOT/'smoke-command.json'
  if cmdfile.exists():commands.append(cmdfile)
  for cmdfile in commands:
   try:request=json.loads(cmdfile.read_text())
   except Exception:continue
   queued=cmdfile.parent==QUEUE
   request_id=request.get('id')
   if queued and (request_id in COMPLETED_IDS or (RESULTS/(str(request_id)+'.json')).exists()):
    cmdfile.unlink(missing_ok=True)
    continue
   if queued:
    try:
     with (CLAIMED/(str(request_id)+'.claimed')).open('x') as claim:
      claim.write(json.dumps({'id':request_id,'action':request.get('action')}))
    except FileExistsError:
     target=RESULTS/(str(request_id)+'.json')
     temp=target.with_suffix('.tmp')
     temp.write_text(json.dumps({'id':request_id,'action':request.get('action'),'error':'Previous execution may have started; not replayed after driver restart'}))
     temp.replace(target);COMPLETED_IDS.add(request_id);cmdfile.unlink(missing_ok=True)
     continue
   if queued or request.get('id')!=last_id:
    request_id=request.get('id')
    if not queued:last_id=request_id
    action=request.get('action');result={'id':request_id,'action':action}
    try:
     if action=='finish':finish=True;result['finished']=True
     elif action=='reinstall':result.update(install_and_launch(request.get('name','retest'),request.get('apk')))
     elif action=='capture':result.update(capture(request.get('name','capture')))
     elif action=='adb':
      rc,out,err=adb(request['args'],timeout=request.get('timeout',60));result.update({'exit':rc,'stdout':out,'stderr':err})
     else:result['error']='Unknown action'
    except Exception as exc:result['error']=repr(exc)
    target=(RESULTS/(str(request_id)+'.json')) if queued else ROOT/'smoke-command-result.json'
    temp=target.with_suffix('.tmp');temp.write_text(json.dumps(result,indent=2));temp.replace(target)
    if queued:
     COMPLETED_IDS.add(request_id)
     cmdfile.unlink(missing_ok=True)
    print('Command result',json.dumps({k:v for k,v in result.items() if k not in ('stdout','stderr')}),flush=True)
    if finish:break
  if finish:break
  time.sleep(1)
except Exception as exc:
 print('ERROR:',repr(exc),flush=True)
 if (ROOT/'emulator-api26.log').exists():print((ROOT/'emulator-api26.log').read_text()[-12000:],flush=True)
 raise
finally:
 if emu is not None and emu.poll() is None:
  emu.terminate()
  try:emu.wait(timeout=15)
  except subprocess.TimeoutExpired:emu.kill()
 subprocess.run([ADB,'kill-server'],env=ENV,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
