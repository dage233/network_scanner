set -e
base_root_path=/ssh_find_script
root_path=/tmp/scanner_test
rm -rf $root_path
project_id=`cat $base_root_path/data/project_conf.json | grep 'project_id' | sed s/\"//g | sed s/\,//g | awk '{print $2}'`

mkdir -p $root_path
cp -r /ssh_find_script $root_path
mv $root_path/ssh_find_script $root_path/$project_id
cd $root_path
tar -cvf $project_id.tar $project_id
cd /tmp/scanner_test/$project_id
python3 run.py
