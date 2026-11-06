from pathlib import Path
import json,time,sys,uuid
root=Path(__file__).resolve().parent
request=json.load(sys.stdin)
if (root/'smoke-stop.flag').exists() and request.get('action')!='finish':
 raise SystemExit('UI automation paused for emulator driver maintenance')
request.setdefault('id',uuid.uuid4().hex)
queue=root/'smoke-queue';queue.mkdir(exist_ok=True)
path=queue/(request['id']+'.json')
temp=path.with_suffix('.tmp');temp.write_text(json.dumps(request));temp.replace(path)
deadline=time.monotonic()+max(180,request.get('timeout',60)+90)
while time.monotonic()<deadline:
 resultfile=root/'smoke-results'/(request['id']+'.json')
 if resultfile.exists():
  try:r=json.loads(resultfile.read_text())
  except Exception:r={}
  if r.get('id')==request['id']:
   print(json.dumps(r,ensure_ascii=False));sys.exit(0)
 time.sleep(.4)
raise SystemExit('Command timed out')
