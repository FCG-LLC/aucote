#!/bin/bash
ddcfg="$HOME/.csapp/deploy-prod.cfg";
if [[ -f "$ddcfg" ]];
	then source $ddcfg; 
	result=`curl --insecure -s -I -X POST --user "$user:$pass" $jenkins/xml | head -n 1 | perl -ne "print 1 if /401 Invalid/"`
	if [ $result ]; then
		echo "Invalid Jenkins credentials !!!, exiting...";
		exit
	fi
else 
	echo "Missing config file $ddcfg";
	echo "Create file with following contents:"
	echo 'jenkins="https://jenkins.cs.int"'
	echo 'user="yourjenkinsuser"'
	echo 'pass="yourjenkinspass"'
	echo '### below you can override deployment host but this works only with --just deploy switch'
	echo 'host="10.12.1.165"'
	echo '### below you can put jenkins job name if autodetect does not work otherwise leave blank'
	echo 'std_job_name=""'
	exit
fi
switch="$1";

######################################################

function deploy(){
	echo "Submiting deploy request to Jenkins";

	queue_no=`curl --insecure -s -i --netrc -X POST --user "$user:$pass" "$jenkins/job/deploy/buildWithParameters?app=$app&host=$host&destEnv=$host" | perl -ne "print /Location:.http.*\/(.*)\//"`;
	queue_url="$jenkins/queue/item/$queue_no/api/json";
	echo "Deploy '$job_name' to $host build queued, waiting for free slot ($queue_url)";
	while [[ `curl --insecure -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'` == "" ]]; do 
		echo -n "."; 
		sleep 1; 
	done

	build_job_no=`curl --insecure -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'`;
	echo "";
	echo "Slot assigned for '$job_name' deployment #$build_job_no, deploying ($jenkins/job/deploy-dev/$build_job_no/)"
	curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print 'ETA: '; print /estimatedDuration..(...)/; print \" s\n\""
	while [[ `curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/deploy-dev/$build_job_no/api/json" | perl -ne "print /building..(.*?),/"` == "true" ]]; do
		echo -n '.'
		sleep 1
	done
	curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/deploy-dev/$build_job_no/api/json" | perl -ne "print \"\nRESULT: \"; print /result..(.*?),/; print \"\n\n\""
}

function check_dep(){
	queue_url="$jenkins/$dep_queue/api/json"
	job_name=`curl --insecure -s --user "$user:$pass" $queue_url | perl -ne "print /Project...name...(.*?)\"/"`
	echo "Sub-task '$job_name' build queued, waiting for free slot ($queue_url)"
	while [[ `curl --insecure -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'` == "" ]]; do 
		echo -n "."; 
		sleep 1; 
	done

	build_job_no=`curl --insecure -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'`;
	echo "";
	echo "Slot assigned for job '$job_name' build #$build_job_no, building ($jenkins/job/$job_name/$build_job_no/)"
	curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print 'ETA: '; print /estimatedDuration..(...)/; print \" s\n\""
	while [[ `curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print /building..(.*?),/"` == "true" ]]; do
		echo -n '.'
		sleep 1
	done
	curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print \"\nRESULT: \"; print /result..(.*?),/; print \"\n\n\""
}

function process_main_job (){
	echo "Submiting build request to Jenkins";
	#app=`echo $job_name | cut -d"-" -f1`;
	queue_no=`curl --insecure -s -i --netrc -X POST --user "$user:$pass" "$jenkins/view/$app%20pipeline/job/$job_name/buildWithParameters?branch=$branch&destEnv=prod&forceWhole=yes" | perl -ne "print /Location:.http.*\/(.*)\//"`;
	queue_url="$jenkins/queue/item/$queue_no/api/json";
	
	echo "Main-task '$job_name' branch $branch build queued, waiting for free slot ($queue_url)";
	while [[ `curl --insecure -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'` == "" ]]; do 
		echo -n "."; 
		sleep 1; 
	done

	build_job_no=`curl --insecure -s --user "$user:$pass" $queue_url | perl -ne 'print /executable.*number..(\d+)/'`;
	echo "";
	
	echo $app;
	echo "Slot assigned for '$job_name' build #$build_job_no, building ($jenkins/job/$job_name/$build_job_no/)"
	curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print 'ETA: '; print /estimatedDuration..(...)/; print \" s\n\""
	while [[ `curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print /building..(.*?),/"` == "true" ]]; do
		echo -n '.'
		sleep 1
	done
	curl --insecure -s -X POST --user "$user:$pass" "$jenkins/job/$job_name/$build_job_no/api/json" | perl -ne "print \"\nRESULT: \"; print /result..(.*?),/; print \"\n\n\""
	## Check for triggered dependant builds
	while [ true ]; do
		echo "Checking for ongoing dependant automatic triggered builds..."

		dep_queue=`curl --insecure -s --user "$user:$pass" $jenkins/queue/api/json | perl -ne "print /build number $build_job_no.*?url...(que.*?)..,/"`	
	
		if [ "$dep_queue" == "" ]; then
			break;
		fi
		check_dep;
	done		
}


branch="tags/$1"
echo "";
if [ "$switch" == "--just-deploy" ]; then
	echo "Will just deploy latest docker to $host"
else
	echo "Will build and then deploy $branch to PROD host, details below"
	echo "--------------------------------";
	git log -1 $branch
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
	if [[ `curl --insecure -s --user "$user:$pass" $jenkins/api/xml | perl -lne "print /<url>(http.*?job\/$job_name\/.*?)<\/url>/g"` == "" ]]; then
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
	echo "Determining proper pipeline for current repo";

	current_repo=`grep url .git/config | cut -d" " -f3`

	search_res='Current repo does not have defined pipeline in Jenkins!'
	joblist=`curl --insecure -s --user "$user:$pass" $jenkins/api/xml | perl -lne "print /<url>(http.*?job.*?)<\/url>/g" | sed 's/http/\\\nhttp/g'`
	while read job;
	do
		if [[ ! $job  =~ "dockerization" ]]; then
			job_repo=`curl --insecure -s -X GET  --user "$user:$pass" $job/config.xml | perl -ne "print /<url>(git.github.*?)<\/url>/g"`;		
			#echo "$job_repo";
			if [[ $job_repo == $current_repo ]]; then 
				job_name=`echo $job | perl -ne "print /job\/(.*)\//"`;
				app=`echo $job_name | cut -d"-" -f1`;
				echo "Reading through jobs in $app pipeline"
				pipelinejobs=`curl --insecure -s --user "$user:$pass" "$jenkins/view/$app%20pipeline/api/xml" | perl -lne "print /<url>(http.*?job.*?)<\/url>/g" | sed 's/http/\\\nhttp/g' | sed 's/\n//'`
				#echo $pipelinejobs
				i=1
				while read pipejob;
				do
					if [ "$pipejob" == "" ];then
						continue
					fi
					job_name=`echo $pipejob | perl -ne "print /job\/(.*)\//"`;
					if [ $i == 1 ]; then
						echo ""
						read -p "You want to start whole build pipeline with first job '$job_name' ? [Y/n] " pipecorrect </dev/tty;
						if [ "$pipecorrect" == "n" ]; then
							((i++))
							continue
						else
						 	echo ""
							echo "-------------------------------------------------------------------------------"
							echo "You can also watch status or detailed logs in $app pipeline:"
							echo "    $jenkins/view/$app%20pipeline"
							echo "-------------------------------------------------------------------------------"
							echo ""
							process_main_job
							search_res='Done processing!';
							break
						fi
						
					fi
					echo ""
					correct=y
					read -p "'$job_name' is this correct job you want start the build with ? [Y/n] " correct </dev/tty;
					if [ "$correct" == "n" ]; then
						echo ""
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
				((i++))
				done <<< "$(echo -e "$pipelinejobs")"
				break
			fi
		fi
	done <<< "$(echo -e "$joblist")"
	echo $search_res;
fi