#!/bin/bash

HEADER_LEN=50

upd_status_header(){
  len=$(( ($HEADER_LEN - ${#1}) / 2 ))
  printf '\n' && printf '#%.0s' $(seq 1 $len) && printf " $1 " && printf '#%.0s' $(seq 1 $len) && printf '\n'
}

upd_status(){
  echo ":: $1"
}

do_install(){
  path=$1

  upd_status_header "Preparing install"
  upd_status "You are currently in $(pwd)"
  start_dir=$(pwd)
  upd_status "Using $path as install path for code repositories"

  upd_status_header "Installing dependencies"
  upd_status "Installing libtins dependencies"
  apt-get --yes install libpcap-dev libssl-dev cmake
  upd_status "Installing libboost (libtins semi dependency)"
  apt-get --yes install libboost-all-dev
  upd_status "Installing aircrack-ng"
  apt-get --yes install aircrack-ng
  upd_status "Installing tcpdump"
  apt-get --yes install tcpdump
  upd_status "Binary dependencies installed"

  upd_status_header "Fetching sources"
  if [ ! -d "$path" ]; then
    upd_status "Install directory does not exist. Creating it..."
    mkdir -p $path
    upd_status "Path created"
  fi
  upd_status "Moving to $path"
  cd $path
  upd_status "Getting dot11decrypt"
  git clone "https://github.com/mfontanini/dot11decrypt.git"
  upd_status "Getting libtins"
  git clone "https://github.com/mfontanini/libtins.git"

  do_compile .
}

do_uninstall(){
  path=$1

  upd_status_header "Uninstalling dependencies"
  upd_status "Uninstalling libtins dependencies"
  apt-get --yes remove --purge libpcap-dev libssl-dev cmake
  upd_status "Uninstalling libboost (libtins semi dependency)"
  apt-get --yes remove --purge libboost-all-dev
  upd_status "Uninstalling aircrack-ng"
  apt-get --yes remove --purge aircrack-ng
  upd_status "Uninstalling tcpdump"
  apt-get --yes remove --purge tcpdump
  upd_status "Binary dependencies uninstalled"

  upd_status_header "Uninstalling libtins"
  upd_status "Entering folder"
  cd $path
  cd libtins/build
  upd_status "Uninstalling..."
  make uninstall
  upd_status "Leaving directory"
  cd ../../
  
  upd_status_header "Removing repo directories"
  upd_status "Removing libtins"
  rm -rf libtins
  upd_status "Removing dot11decrypt"
  rm -rf dot11decrypt
  rm -f /usr/bin/dot11decrypt
  upd_status "Leaving directory"
  cd

  echo "Do you wish to remove $path as well?"
  select yn in "Yes" "No"; do
    case $yn in
      Yes ) rm -rf $path; break;;
      No ) exit;;
    esac
  done

  upd_status_header "Conclusion"
  upd_status "dot11decrypt has been successfully uninstalled"
  upd_status "Note: You may want to run sudo apt-get autoremove to clear unused packages"
}

do_compile(){
  path=$1

  upd_status_header "Selecting correct dir"
  upd_status "Moving into $1"
  cd $path

  upd_status_header "Configuring  libtins"
  upd_status "Creating build folder"
  cd libtins
  mkdir build
  upd_status "Entering build folder"
  cd build
  upd_status "Fetching missing submodules"
  git submodule init && git submodule update
  upd_status "Running cmake"
  cmake ../ -DLIBTINS_ENABLE_CXX11=1
  upd_status "Running make"
  make
  upd_status "Running install"
  make install
  upd_status "Install finished."
  upd_status "Updating cache..."
  ldconfig
  upd_status "Exiting libtins folder"
  cd ../../

  upd_status_header "Configuring dot11decrypt"
  upd_status "Creating build folder"
  cd dot11decrypt
  mkdir build
  upd_status "Entering build folder"
  cd build
  upd_status "Running cmake"
  cmake ../
  upd_status "Runing make" 
  make
  upd_status "Linking binary file"
  ln -sf "$(pwd)/dot11decrypt" /usr/bin/dot11decrypt
  upd_status "Exiting dot11decrypt folder"
  cd ../../
}

get_network_channel(){
  countdown=3
  channel=""
  while [ $countdown -gt 0 ] && [ "$channel" == "" ]; do
    channel="$(sudo iw dev $interface scan | sed -n -e "/SSID: $ssid/,/Extended capabilities/ p" | grep 'primary channel' | cut -d\  -f5)"
    countdown=$(( $countdown-1 ))
  done
  echo $channel
}

do_setup(){
  interface=$1
  ssid=$2
  pw=$3

  upd_status_header "Retrieving prescan data"
  upd_status "Fetching network properties"
  # prescan for network channel (cannot be done in monitor mode)
  channel=$(get_network_channel)

  # Setup monitor mode
  upd_status_header "Entering monitor mode"
  upd_status "Using interface $interface"
  # Try to use aircrack-ng to enter monitor mode
  upd_status "Entering monitor mode..."
  mon_if="$(sudo airmon-ng start $interface | grep enabled | cut -d ] -f3 | cut -d \) -f1)"
  if [ "$mon_if" == "" ]; then
    echo "There was a problem entering monitor mode. Run 'sudo airmon-ng start $interface' to manually debug" 1>&2
    exit 1
  else
    echo "Monitor interface set up with name $mon_if"
  fi

  # Setup settings required for everything to run smoothly
  upd_status_header "Adjusting additional settings"
  # Set channel to the one of the given network
  upd_status "Setting channel..."
  if [ "$channel" != "" ]; then
    sudo iwconfig $mon_if channel $channel > /dev/null
    ch_channel="$(sudo iw dev | sed -n -e "/Interface $mon_if/,/txpower/ p" | grep channel | cut -d\  -f2)"
    if [ "$ch_channel" == "$channel" ]; then
      echo "Channel successfully set to $channel"
    else
      echo "Error while setting channel. Tried to set channel $channel, failed. Interface still uses channel $ch_channel"
      exit 3
    fi
  else
    echo "Could not acquire desired network channel for $ssid. Did you spell it correctly?"
    exit 2
  fi

  # Print happy success message
  upd_status_header "Conclusion"
  upd_status "Network adapter setup done!"
  upd_status "Starting dot11decrypt"
  dot11decrypt $mon_if "wpa:$ssid:$pw"
}

remove_setup(){
  interface=$1

  upd_status_header "Remove changes"
  upd_status "Removing monitor mode from adapter $interface"
  airmon-ng stop $interface

  upd_status_header "Conclusion"
  upd_status "All changes is reversed"
}

do_listen(){
  tcpdump -i tap0 -w $1 -s 65535
}

do_create_ha_services(){
  interface=$1
  ssid=$2
  ssid_pw=$3
  ha_path=$4
  mh_path=$(pwd)

  upd_status_header "Creating files"
  upd_status "Creating capture service"
  echo -e "[Unit]\nDescription=Captures traffic and publishes in files\nAfter=network.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart=/usr/sbin/tcpdump -i tap0 -G 5 -w '$ha_path/traces/trace_%%Y%%m%%d-%%H%%M%%S.pcap'\n\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/trafficcapture.service
  upd_status "Creating decryption service"
  echo -e "[Unit]\nDescription=Decrypts traffic from monitor mode packet stream\nAfter=network.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5\nExecStart=$mh_path/monitor-help.sh start $interface $ssid $ssid_pw\nExecStop=$mh_path/monitor-help.sh stop ${interface}mon\n\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/trafficdecrypter.service

  upd_status_header "Running services"
  upd_status "Reloaded services"
  systemctl daemon-reload
  upd_status "Enabled decryption service on bootup"
  systemctl enable trafficdecrypter.service
  upd_status "Starting encryption service..."
  systemctl start trafficdecrypter.service
  upd_status "Encryption service started!"

  upd_status_header "Summary"
  upd_status "Services created."
  upd_status "Please run again if any of the following changes:"
  upd_status "  1. The location of this file"
  upd_status "  2. Your hass path"
  upd_status "  3. Your network properties"
  upd_status ""
  upd_status "NOTE: Capture service is not running. To start, use 'sudo systemctl start trafficcapture.service'"
  upd_status "The traffic capture service prints all captured data to files on your hard drive."
  upd_status "If the home assistant component which consumes these files are not running but you still keep the capture service running,"
  upd_status "make sure to flush them in some way. Our recommended way is to run a cronjob to clear the cache every hour."
  upd_status "If you wish to add this cronjob, run '(crontab -l ; echo \"  0 *  *   *   *     rm -f $ha_path/traces/*.pcap\") | crontab'"
  echo ""
}



if [ "$EUID" -ne 0 ] && [ "$1" != "help" ]
  then echo "Please run as root."
  exit -1
else
  if [ "$1" == "start" ]; then
    echo "Starting setup...."
    do_setup $2 $3 $4
  elif [ "$1" == "stop" ]; then
    echo "Removing setup..."
    remove_setup $2
  elif [ "$1" == "install" ]; then
    echo "This will install dot11decrypt with $2 as installation folder. Do you wish to continue?"
    select yn in "Yes" "No"; do
      case $yn in
        Yes ) do_install $2; break;;
        No ) exit;;
      esac
    done
  elif [ "$1" == "uninstall" ]; then
    echo "This will uninstall dot11decrypt from $2 and all its dependencies. Do you wish to continue?"
    select yn in "Yes" "No"; do
      case $yn in
        Yes ) do_uninstall $2; break;;
        No ) exit;;
      esac
    done
  elif [ "$1" == "build" ]; then
    echo "This will rebuild dot11decrypt with $2 as installation folder. Do you wish to continue?"
    select yn in "Yes" "No"; do
      case $yn in
        Yes ) do_compile $2; break;;
        No ) exit;;
      esac
    done
  elif [ "$1" == "listen" ]; then
    do_listen $2
  elif [ "$1" == "ha_services" ]; then
    echo "This requires some more information in order to start services correctly."
    read -e -p "What network interface? " -i "wlan0" nic
    read -e -p "What network name? " -i "" ssid
    read -e -p "What network password? " -i "" ssid_pw
    USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
    read -e -p "Homeassistant config dir? " -i "$USER_HOME/.homeassistant" ha_dir
    do_create_ha_services $nic $ssid $ssid_pw $ha_dir
  elif [ "$1" == "help" ]; then
    echo -e "All utilities in this script requires sudo"
    echo -e "There are 6 different commands provided:\n"
    echo -e "\tstart [interface] [ssid] [pw] : Sets interface in monitor mode and starts decrypting"
    echo -e "\t\tRequirements: The interface should be in managed mode before this is run.\n"
    echo -e "\tstop [interface]              : Stops the monitor mode and decryption"
    echo -e "\t\tRequirements: None.\n"
    echo -e "\tlisten [outputfile]           : Listen to the decrypted traffic and outputs a .pcap file"
    echo -e "\t\tRequirements: The start command should be running while issuing this command\n"
    echo -e "\tinstall [path]                : Makes a full install of all software needed. The given path will be used for storing code repo dependencies"
    echo -e "\t\tRequirements: It is recommended to run sudo apt-get update before issuing this command.\n"
    echo -e "\tbuild [path]                  : Builds the packages found in the given path (limited to libtins and dot11decrypt)"
    echo -e "\t\tRequirements: All dependencies needs to be installed. See the install command.\n"
    echo -e "\tha_services                   : Generates nw capture services for your home assistant installation"
    echo -e "\t\tRequirements: Move this file to a permanent location before issuing this command\n"
    echo -e "\tuninstall [path]              : Removes all installed packages and dependencies. WARNING! Some dependencies might be used by other programs"
    echo -e "\t\tRequirements: None. You might want to run sudo apt-get autoremove after the uninstall though, in order to clear out packages.\n"
    echo -e "\thelp                          : Brings up this info.\n"
  else
    echo "Usage: setup.sh [start|stop|install|build|ha_services|uninstall|help]"
  fi
fi
