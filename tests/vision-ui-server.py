"""Disposable browser fixture; synthetic local model, real admin API and image validation."""
import importlib.util,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('vision_ops_fixture',ROOT/'tests/test_ops_api.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
case=f.OpsApi();case.setUp()
from app_modules import meal_photo
meal_photo.CONFIG=case.ops_mod.VISION_CONFIG
meal_photo.recognize=lambda blob:{'food_name':'合成测试米饭','components':[meal_photo.Component(name='米饭',grams=100,kcal100=130,protein100=2.69,carbs100=28.17,fat100=.28).model_dump()],'totals':{'cal':130},'note':'synthetic model fixture'}
try:
 import uvicorn
 uvicorn.run(case.ops_mod.app,host='127.0.0.1',port=18024,log_level='warning')
finally:case.ops.close();case.app.close();case.bare.close();case.tearDown()
