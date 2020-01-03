from pprint import pprint

from NauNetTools.Clients.JwcClient import JwcClient

if __name__ == '__main__':
    print('User Name: ', end='')
    username = input()
    print('Password: ', end='')
    password = input()

    print('Try Login ... ...')
    client = JwcClient()
    print('Login Result: ' + str(client.login(username, password)))
    print('Function: ')
    pprint(client.get_function_dict())
