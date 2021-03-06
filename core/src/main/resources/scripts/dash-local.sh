#!/bin/bash -e

: ${LOGFILE:=/var/log/recipes/dash-local.log}

: ${SOURCE_DIR:=/data/jars}
: ${STORAGE_JAR:=dash-azure-storage-2.2.0.jar}
: ${MR_TAR_NAME:=mapreduce.tar.gz}
: ${TEZ_TAR_NAME:=tez.tar.gz}
: ${TMP_EXTRACT_DIR:=temp_extract_dir}

restart_services(){
  if [ -f /var/run/oozie/oozie.pid ] && jps | grep -wq "$(cat /var/run/oozie/oozie.pid)"; then
    su oozie -c '/usr/hdp/current/oozie-server/bin/oozie-stop.sh'
    su oozie -c '/usr/hdp/current/oozie-server/bin/oozie-start.sh'
  fi
}

set_spark_cp(){
  SPARK_ENV='/usr/hdp/current/spark-client/conf/spark-env.sh'
  SPARK_CP='SPARK_CLASSPATH=$SPARK_CLASSPATH:/usr/hdp/current/hadoop-client/lib/dash-azure-storage-2.2.0.jar:/usr/hdp/current/hadoop-client/hadoop-azure.jar'
  if [ -f /usr/hdp/current/spark-client/conf/spark-env.sh ] && ! grep -q "$SPARK_CP" $SPARK_ENV; then
    echo "$SPARK_CP" >> $SPARK_ENV
  fi
}

main(){
  SOURCE_JAR="$SOURCE_DIR/$STORAGE_JAR"
  if [ ! -f "$SOURCE_JAR" ]; then
    echo 'DASH storage jar not found in the source directory, downloading it to /tmp.'
    SOURCE_JAR="/tmp/$STORAGE_JAR"
    curl -o "$SOURCE_JAR" "https://www.dash-update.net/client/Latest/StorageSDK2.0/$STORAGE_JAR";
  fi

  echo "Replacing azure-storage.jar with $STORAGE_JAR"
  find / -name "azure-storage*.jar" | while read line; do echo "Replacing $line"; \cp -f "$SOURCE_JAR" "${line%azure*}"; rm -f $line; done

  tar_files=$(find / -regextype posix-extended -regex "^(.*$MR_TAR_NAME|.*$TEZ_TAR_NAME)$")
  for tar_file in $tar_files; do
    if [ -f $tar_file ]; then
      cd ${tar_file%$(basename $tar_file)}

      rm -rf $TMP_EXTRACT_DIR && mkdir $TMP_EXTRACT_DIR && cd $TMP_EXTRACT_DIR

      echo "Extracting $tar_file."
      tar -xzf $tar_file

      echo "Replacing azure-storage.jar with $STORAGE_JAR."
      find . -name "azure-storage*.jar" | while read line; do echo "Replacing $line"; \cp -f $SOURCE_JAR ${line%azure*}; rm -f $line; done

      echo "Removing $tar_file."
      rm -f "$tar_file"

      echo "Creating new $MR_TAR_NAME with the replaced libs."
      tar -zcf "$tar_file" $(ls)

      echo "Cleaning up extracted directory."
      cd .. && rm -rf $TMP_EXTRACT_DIR
    fi
  done

  restart_services
  set_spark_cp
}

exec &>> "$LOGFILE"
[[ "$0" == "$BASH_SOURCE" ]] && main "$@"
