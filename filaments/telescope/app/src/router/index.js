import {createRouter, createWebHistory} from 'vue-router'

const routes = [
  {
    path: '/processes',
    name: 'processes',
    meta: {text: "Processes"},
    component: () => import('../components/ps/Tree'),
  },
  {
    path: '/processes/:pid',
    name: 'process',
    meta: {text: "Process"},
    props: true,
    component: () => import('../components/ps/Process')
  },
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
