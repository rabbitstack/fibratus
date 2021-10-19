<template>
  <el-container>
    <el-aside>
  <el-menu class="navmenu" background-color="#192A4E" text-color="#fff" router="true" default-active="/">
    <el-menu-item index="/processes">
      <ion-icon name="terminal-outline"></ion-icon>
      <span> Processes</span>
    </el-menu-item>
    <el-menu-item index="/about">
      <ion-icon name="folder-outline"></ion-icon>
      <span> Directories</span>
    </el-menu-item>
    <el-menu-item index="/profile">
      <ion-icon name="cube-outline"></ion-icon>
      <span> Registry</span>
    </el-menu-item>
    <el-menu-item index="/profile1">
      <ion-icon name="file-tray-full-outline"></ion-icon>
      <span> Files</span>
    </el-menu-item>
    <el-menu-item index="/connections">
      <ion-icon name="wifi-outline"></ion-icon>
      <span> Connections</span>
    </el-menu-item>
    <el-menu-item index="/threads">
      <ion-icon name="flash-outline"></ion-icon>
      <span> Threads</span>
    </el-menu-item>
    <el-menu-item index="/errors">
      <ion-icon name="bug-outline"></ion-icon>
      <span> Errors</span>
    </el-menu-item>
    <el-menu-item index="/handles">
      <ion-icon name="bag-handle-outline"></ion-icon>
      <span> Handles</span>
    </el-menu-item>
    <el-menu-item index="/dlls">
      <ion-icon name="bag-handle-outline"></ion-icon>
      <span> DLLs</span>
    </el-menu-item>
    <el-menu-item index="/ports">
      <ion-icon name="bag-handle-outline"></ion-icon>
      <span> Server Ports</span>
    </el-menu-item>
    <el-menu-item index="/slowio">
      <ion-icon name="stats-chart-outline"></ion-icon>
      <span> Slow File I/O</span>
    </el-menu-item>
    <el-menu-item index="/pe">
      <ion-icon name="stats-chart-outline"></ion-icon>
      <span> PE</span>
    </el-menu-item>
  </el-menu>
    </el-aside>


  <el-container>
    <el-main>
      <router-view/>
    </el-main>
  </el-container>

  </el-container>
</template>
<style>

@import url('https://fonts.googleapis.com/css2?family=Jost:wght@300;400;500&display=swap');

html, body {
  margin: 0;
  min-height: 100% !important;
  height: 100%;
  font-family: Jost, Source Sans Pro, Helvetica Neue, Arial, sans-serif;
}

main {
  background-color: #f6f7f8;
}

aside {
  max-width: 230px;
  height: 100%;
}

.navmenu {
  max-width: 230px;
  padding-top: 20px;
  height: 100vh;
  font-family: Jost, Source Sans Pro, Helvetica Neue, Arial, sans-serif;
}

ion-icon {
  --ionicon-stroke-width: 40px;
  font-size: 20px;
}

ul .el-menu-item {
  height: 40px;
  font-weight: 500;
  line-height: 38px;
  text-align: left;
}

ul .el-menu-item.is-active {
  background-color: rgba(150, 167, 223, .45) !important;
  color: #fff;
  border-radius: 3px;
  margin: 0 12px 0 12px;
}

#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

#nav a.router-link-exact-active {
  color: #42b983;
}
</style>
