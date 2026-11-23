FROM manjarolinux/base:latest
RUN pacman -Syu --noconfirm --needed xorg-server-xvfb xorg-xauth mesa mesa-utils gtk3 webkit2gtk-4.1 libayatana-appindicator librsvg xfwm4 xdotool imagemagick tesseract tesseract-data-eng tesseract-data-rus ttf-dejavu dbus xorg-xdpyinfo && useradd --create-home qa
COPY render.sh /usr/local/bin/render.sh
RUN chmod 755 /usr/local/bin/render.sh && dbus-uuidgen --ensure=/etc/machine-id
USER qa
WORKDIR /home/qa
ENTRYPOINT ["dbus-run-session","--","/usr/local/bin/render.sh"]
