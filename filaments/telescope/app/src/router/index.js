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
  {
    path: '/files',
    name: 'files',
    meta: {text: "Files"},
    props: true,
    component: () => import('../components/file/Files')
  },

  {
    path: '/ingress',
    name: 'ingress',
    meta: {text: "Ingress Packets"},
    props: true,
    component: () => import('../components/packet/Ingress')
  },
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
