<template>
  <article style="height: 100%;">
    <router-view></router-view>
    <!--需要缓存的路由-->
    <keep-alive>
      <router-view name="cache"></router-view>
    </keep-alive>
  </article>
</template>
