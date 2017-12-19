using Cache.Factory;
using Cache.Factory.CacheType;
using Cache.Factory.Interfaces;

namespace Security.Framework.Cache
{
    public class UtilCache
    {
        private static readonly UtilCache instancia = new UtilCache();

        private static ICacheBehavior _AppFabricInstance;
        private static ICacheBehavior _MemoryInstance;
        private static ICacheBehavior _DBCacheInstance;
        private static ICacheBehavior _EnterpriseInstance;

        public static void InitCache(ECacheType tipoCache)
        {
            switch (tipoCache)
            {
                case ECacheType.AppFabricCache:
                    _AppFabricInstance = FactoryCacheHelper.GetCacheType(ECacheType.AppFabricCache);
                    break;

                case ECacheType.CachingRuntimeCache:
                    _MemoryInstance = FactoryCacheHelper.GetCacheType(ECacheType.CachingRuntimeCache);
                    break;

                case ECacheType.CacheBD:
                    _DBCacheInstance = FactoryCacheHelper.GetCacheType(ECacheType.CacheBD);
                    break;

                case ECacheType.EnterpriseLibraryCache:
                    _EnterpriseInstance = FactoryCacheHelper.GetCacheType(ECacheType.EnterpriseLibraryCache);
                    break;
            }
        }

        public static UtilCache Instancia
        {
            get { return UtilCache.instancia; }
        }

        public static ICacheBehavior AppFabricInstance
        {
            get { return UtilCache._AppFabricInstance; }
        }

        public static ICacheBehavior MemoryInstance
        {
            get { return UtilCache._MemoryInstance; }
        }

        public static ICacheBehavior DBCacheInstance
        {
            get { return UtilCache._DBCacheInstance; }
        }

        public static ICacheBehavior EnterpriseInstance
        {
            get { return UtilCache._EnterpriseInstance; }
        }

        public bool CleanCache(ECacheType tipoCache)
        {
            bool result = false;
            switch (tipoCache)
            {
                case ECacheType.AppFabricCache:
                    result = _AppFabricInstance.CleanCache();
                    _AppFabricInstance = null;
                    break;

                case ECacheType.CachingRuntimeCache:
                    result = _MemoryInstance.CleanCache();
                    _MemoryInstance = null;
                    break;

                case ECacheType.CacheBD:
                    result = _DBCacheInstance.CleanCache();
                    _DBCacheInstance = null;
                    break;

                case ECacheType.EnterpriseLibraryCache:
                    result = _EnterpriseInstance.CleanCache();
                    _EnterpriseInstance = null;
                    break;
            }

            return result;
        }
    }
}