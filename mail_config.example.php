<?php
return [
    // Почтовый ящик должен быть создан на reg.ru или другом SMTP-сервисе.
    // Для почты reg.ru обычно используется mail.hosting.reg.ru, порт 465, SSL.
    'host' => 'mail.hosting.reg.ru',
    'port' => 465,
    'secure' => 'ssl',
    'username' => 'no-reply@mincifra-practica.ru',
    'password' => 'PASSWORD_FROM_MAILBOX',
    'from_email' => 'no-reply@mincifra-practica.ru',
    'from_name' => 'Практика.Цифра',
];
