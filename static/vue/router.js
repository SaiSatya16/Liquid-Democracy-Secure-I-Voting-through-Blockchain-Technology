import Home from './components/home.js';
import About from './components/about.js';
import Registration from './components/registration.js';
import Login from './components/login.js';


const routes = [
    {
        path: '/',
        component: Home,
        name: 'Home'
    },
    {
        path: '/about',
        component: About,
        name: 'About'
    },
    {
        path: '/register',
        component: Registration,
        name: 'Register'
    },
    {
        path: '/login',
        component: Login,
        name: 'Login'
    },
    {
        path: "*",
        redirect: "/"
    }
];

const router = new VueRouter({
    routes,
});

export default router;