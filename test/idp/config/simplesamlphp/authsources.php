<?php

$config = array(

    'admin' => array(
        'core:AdminPassword',
    ),

    'example-userpass' => array(
        'exampleauth:UserPass',
        'aa:aa' => array(
            'uid' => array('1'),
            'eduPersonAffiliation' => array('group1'),
            'email' => 'aa@route443.dev',
            'givenName' => 'Alan',
            'surName' => 'Alda',
            'telephoneNumber' => '+31(0)12345678',
            'company' => 'NGINX Inc.',
        ),
        'bb:bb' => array(
            'uid' => array('2'),
            'eduPersonAffiliation' => array('group2'),
            'email' => 'bb@route443.dev',
            'givenName' => 'Ben',
            'surName' => 'Bernanke',
            'telephoneNumber' => '+31(0)12345678',
            'company' => 'NGINX Inc.',
        ),
    ),

);
