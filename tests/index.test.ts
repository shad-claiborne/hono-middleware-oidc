import dotenv from 'dotenv';
import { describe, expect, test } from 'vitest';
import axios from 'axios';

dotenv.config();

describe("Hono OIDC middleware", async () => {
    // const app = new Hono()

    // app.use('*', except('/auth/callback', withIdentity));

    // app.use('/auth/callback', forAuthorization);

    // app.get('/async/api/identity', async (c) => {
    //     return c.json(c.get('identity'));
    // });

    // app.get('/', async (c) => {
    //     return c.text('hello world');
    // });

    // test('Identity', async () => {
    //     let req = new Request('http://localhost/identity')
    //     let res: any = await app.request(req);
    //     expect(res).not.toBeNull();
    //     expect(res.status).toEqual(302);
    // let location = res.headers.get('location');
    // console.log(res.headers);
    // expect(location).not.toBeNull();

    // res = await axios.get(location as string, {
    //     maxRedirects: 0,
    //     validateStatus: status => status === 302,
    // });
    // expect(res.status).toEqual(302);
    // location = res.headers.get('location');
    // req = new Request(location);
    // res = await app.request(req);
    // });
});