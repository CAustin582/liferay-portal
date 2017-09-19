FROM mdelapenya/liferay-portal-nightlies:20170914
MAINTAINER Sergio González <sergio.gonzalez@liferay.com>

COPY deploy/*.?ar $LIFERAY_HOME/osgi/modules/
COPY supervisord-tomcat.conf /etc/supervisor/conf.d/supervisord-tomcat.conf
COPY portal-ext.properties /liferay/portal-ext.properties