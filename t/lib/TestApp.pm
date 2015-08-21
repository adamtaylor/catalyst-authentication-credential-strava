package TestApp;
 
use Moose;
 
extends 'Catalyst';
 
__PACKAGE__->config(
    'Plugin::Authentication' => {
        default => {
            credential => {
                class         => 'Strava',
                client_id     => $ENV{FACEBOOK_APPLICATION_ID},
                clinet_secret => $ENV{FACEBOOK_APPLICATION_SECRET},
            },
            store => {
                class => 'Null',
            },
        },
    },
);
 
__PACKAGE__->setup(qw(
    Authentication
));
 
1;
