#!/bin/bash
ddcfg="$HOME/.csapp/deploy-dev.cfg";
if [[ -f "$ddcfg" ]];
	then source $ddcfg; 
	result=`curl -s -I -X POST --user "$user:$pass" $jenkins/xml | head -n 1 | perl -ne "print 1 if /401 Invalid/"`
	if [ $result ]; then
		echo "Invalid Jenkins credentials !!!, exiting...";
		exit
	fi
else 
	echo "Missing config file $ddcfg";
	echo "Create file with following contents:"
	echo 'jenkins="http://10.12.1.110:8080"'
	echo 'user="yourjenkinsuser"'
	echo 'pass="lyourjenkinspass"'
	echo '### below you can override deployment host'
	echo 'host="10.12.1.175"'
	echo '### below you can put jenkins job name if autodetect does not work otherwise leave blank'
	echo 'std_job_name=""'
	exit
fi
switch="$1";

######################################################

function deploy(){
	echo "Submiting deploy request to Jenkins";

	queue_no=`curl -s -i --netrc -X POST --user "$user:$pass" "$jenkins/job/deploy-dev/buildWithParameters?app=$app&host=$host" | perl -ne "print /Location:.http.*\/(.*)\//"`;
	queue_url="$jenkins/queue/item/$queue_no/api/json";
	echo "Deploy '$job_name' to $host build queued, waiting for free slot ($queue_url)";
	while [[ `curl -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'` == "" ]]; do 
		echo -n "."; 
		sleep 2; 
	done

	build_job_no=`curl -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'`;
	echo "";
	echo "Slot assigned for '$job_name' deployment #$build_job_no, deploying ($jenkins/job/deploy-dev/$build_job_no/)"
	curl -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print 'ETA: '; print /estimatedDuration..(...)/; print \" s\n\""
	while [[ `curl -s -X POST --user "$user:$pass" "$jenkins/job/deploy-dev/$build_job_no/api/json" | perl -ne "print /building..(.*?),/"` == "true" ]]; do
		echo -n '.'
		sleep 2
	done
	curl -s -X POST --user "$user:$pass" "$jenkins/job/deploy-dev/$build_job_no/api/json" | perl -ne "print \"\nRESULT: \"; print /result..(.*?),/; print \"\n\n\""
}

function check_dep(){
	queue_url="$jenkins/$dep_queue/api/json"
	job_name=`curl -s --user "$user:$pass" $queue_url | perl -ne "print /name...(.*?)\"/"`
	echo "Sub-task '$job_name' build queued, waiting for free slot ($queue_url)"
	while [[ `curl -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'` == "" ]]; do 
		echo -n "."; 
		sleep 2; 
	done

	build_job_no=`curl -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'`;
	echo "";
	echo "Slot assigned for job '$job_name' build #$build_job_no, building ($jenkins/job/$job_name/$build_job_no/)"
	curl -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print 'ETA: '; print /estimatedDuration..(...)/; print \" s\n\""
	while [[ `curl -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print /building..(.*?),/"` == "true" ]]; do
		echo -n '.'
		sleep 2
	done
	curl -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print \"\nRESULT: \"; print /result..(.*?),/; print \"\n\n\""
}

function process_main_job (){
	echo "Submiting build request to Jenkins";
	queue_no=`curl -s -i --netrc -X POST --user "$user:$pass" $jenkins/job/$job_name/buildWithParameters?branch=$branch | perl -ne "print /Location:.http.*\/(.*)\//"`;
	queue_url="$jenkins/queue/item/$queue_no/api/json";
	echo "Main-task '$job_name' branch $branch build queued, waiting for free slot ($queue_url)";
	while [[ `curl -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'` == "" ]]; do 
		echo -n "."; 
		sleep 2; 
	done

	build_job_no=`curl -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'`;
	echo "";
	
	echo $app;
	echo "Slot assigned for '$job_name' build #$build_job_no, building ($jenkins/job/$job_name/$build_job_no/)"
	curl -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print 'ETA: '; print /estimatedDuration..(...)/; print \" s\n\""
	while [[ `curl -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print /building..(.*?),/"` == "true" ]]; do
		echo -n '.'
		sleep 2
	done
	curl -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print \"\nRESULT: \"; print /result..(.*?),/; print \"\n\n\""
	## Check for triggered dependant builds
	while [ true ]; do
		echo "Checking for ongoing dependant automatic triggered builds..."

		dep_queue=`curl -s --user "$user:$pass" $jenkins/queue/api/json | perl -ne "print /build number $build_job_no.*?url...(que.*?)..,/"`	
	
		if [ "$dep_queue" == "" ]; then
			echo "Build ready to deploy"
			deploy;
			break;
		fi
		check_dep;
	done		
}


branch=`git branch | grep '*' | cut -f2 -d" "`
echo "";
if [ "$switch" == "--just-deploy" ]; then
	echo "Will just deploy latest docker to $host"
else
	echo "Will build and then deploy last pushed commit in $branch to $host, details below"
	echo "--------------------------------";
	git log -1 origin/$branch
	echo "--------------------------------";
	if [ "$branch" == "master" ]; then
		read -p "You are building and deploying above commit from MASTER branch to DEV host, are you sure ? [y/N] " sure </dev/tty;
		if [ "$sure" != "y" ]; then
			exit;
		fi
	fi
fi

if [ "$std_job_name" ]; then
	job_name="$std_job_name";
	if [[ `curl -s --user "$user:$pass" $jenkins/api/xml | perl -lne "print /<url>(http.*?job\/$job_name\/.*?)<\/url>/g"` == "" ]]; then
		echo "No job named '$job_name' in Jenkins dedfined!!";
	else
		if [ "$switch" == "--just-deploy" ]; then
			deploy;
		else
			process_main_job;
		fi
		echo 'Done processing!';
	fi
else
	echo "Determining proper job for current repo";

	current_repo=`grep url .git/config | cut -d" " -f3`

	search_res='Current repo not defined anywheree in Jenkins!'
	joblist=`curl -s --user "$user:$pass" $jenkins/api/xml | perl -lne "print /<url>(http.*?job.*?)<\/url>/g" | sed 's/http/\nhttp/g'`
	while read job;
	do
		if [[ ! $job  =~ "dockerization" ]]; then
			job_repo=`curl -s -X GET  --user "$user:$pass" $job/config.xml | perl -ne "print /<url>(git.github.*?)<\/url>/g"`;		
			if [[ $job_repo == $current_repo ]]; then 
				job_name=`echo $job | perl -ne "print /job\/(.*)\//"`;
				app=`echo $job_name | cut -d"-" -f1`;
				if [[ ! "$job_name" =~ "unit_test" ]]; then

					read -p "'$job_name' is this correct job ? [Y/n] " correct </dev/tty;
					if [ "$correct" == "n" ]; then
						echo "Trying to find next matching job....";
						search_res='No more matching jobs found!'
					else
						if [ "$switch" == "--just-deploy" ]; then
							deploy;
						else
							process_main_job;
						fi
						search_res='Done processing!';	
						break
					fi
				fi
			fi
		fi
	done <<< "$(echo -e "$joblist")"
	echo $search_res;
fi