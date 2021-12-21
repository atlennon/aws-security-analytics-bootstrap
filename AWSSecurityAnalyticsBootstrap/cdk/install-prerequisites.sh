curl -sL https://rpm.nodesource.com/setup_14.x | sudo bash -
yum -y install nodejs
npm install -g aws-cdk
yum -y install git
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install