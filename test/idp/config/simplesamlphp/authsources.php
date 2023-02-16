<?php

$config = array(

    'admin' => array(
        'core:AdminPassword',
    ),

    'example-userpass' => array(
        'exampleauth:UserPass',
        'aa:aa' => array(
            'uid' => array('1'),
            'memberOf' => array('group1, admins, students'),
            'email' => 'user1@route443.dev',
            'name' => 'Alan Alda',
            'telephoneNumber' => '+31(0)12345678',
            'company' => 'NGINX Inc.',
        ),
        'bb:bb' => array(
            'uid' => array('2'),
            'memberOf' => array('group2, users, students'),
            'email' => 'user2@route443.dev',
            'name' => 'Ben Bernanke',
            'telephoneNumber' => '+31(0)12345678',
            'company' => 'NGINX Inc.',
        ),
    ),

);
