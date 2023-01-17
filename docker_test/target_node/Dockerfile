FROM ubuntu
COPY requirements.txt /
RUN echo 1 && \
sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
sed -i s@/security.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
apt-get update && \
apt-get install -y vim net-tools nmap openssh-server openssh-client python3 python3-pip && \
sed -i 's/^.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config && \
sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
RUN python3 -m pip install --upgrade pip
RUN pip3 install -r /requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
RUN mkdir /run/sshd
CMD ["/usr/sbin/sshd", "-D"]