/*
 *    Copyright (c) 2025 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include <app/server-cluster/ServerClusterInterface.h>
#include <pw_unit_test/framework.h>

#include <app-common/zap-generated/ids/Attributes.h>
#include <app/ConcreteClusterPath.h>
#include <app/server-cluster/DefaultServerCluster.h>
#include <app/server-cluster/ServerClusterContext.h>
#include <app/server-cluster/SingleEndpointServerClusterRegistry.h>
#include <app/server-cluster/testing/TestServerClusterContext.h>
#include <lib/core/CHIPError.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/StringBuilderAdapters.h>

#include <algorithm>
#include <cstdlib>
#include <random>

using namespace chip;
using namespace chip::Test;
using namespace chip::app;
using namespace chip::app::DataModel;
using namespace chip::app::Clusters;

namespace {

constexpr chip::EndpointId kEp1     = 1;
constexpr chip::EndpointId kEp2     = 2;
constexpr chip::EndpointId kEp3     = 3;
constexpr chip::ClusterId kCluster1 = 1;
constexpr chip::ClusterId kCluster2 = 2;
constexpr chip::ClusterId kCluster3 = 3;

class FakeServerClusterInterface : public DefaultServerCluster
{
public:
    FakeServerClusterInterface(const ConcreteClusterPath & path) : DefaultServerCluster(path) {}
    FakeServerClusterInterface(EndpointId endpoint, ClusterId cluster) : DefaultServerCluster({ endpoint, cluster }) {}

    DataModel::ActionReturnStatus ReadAttribute(const DataModel::ReadAttributeRequest & request,
                                                AttributeValueEncoder & encoder) override
    {
        switch (request.path.mAttributeId)
        {
        case Globals::Attributes::FeatureMap::Id:
            return encoder.Encode<uint32_t>(0);
        case Globals::Attributes::ClusterRevision::Id:
            return encoder.Encode<uint32_t>(123);
        }
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    bool HasContext() { return mContext != nullptr; }

    const ConcreteClusterPath & GetPath() const { return mPath; }
};

class MultiPathCluster : public DefaultServerCluster
{
public:
    MultiPathCluster(Span<const ConcreteClusterPath> paths) : DefaultServerCluster(paths[0]), mActualPaths(paths) {}

    DataModel::ActionReturnStatus ReadAttribute(const DataModel::ReadAttributeRequest & request,
                                                AttributeValueEncoder & encoder) override
    {
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }

    Span<const ConcreteClusterPath> GetPaths() const override { return mActualPaths; }

private:
    Span<const ConcreteClusterPath> mActualPaths;
};

class CannotStartUpCluster : public FakeServerClusterInterface
{
public:
    CannotStartUpCluster(EndpointId endpoint, ClusterId id) : FakeServerClusterInterface(endpoint, id) {}
    CHIP_ERROR Startup(ServerClusterContext & context) override { return CHIP_ERROR_BUSY; }
};

struct TestSingleEndpointServerClusterRegistry : public ::testing::Test
{
    static void SetUpTestSuite() { ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR); }
    static void TearDownTestSuite() { chip::Platform::MemoryShutdown(); }
};

} // namespace

TEST_F(TestSingleEndpointServerClusterRegistry, BasicTest)
{
    SingleEndpointServerClusterRegistry registry;

    FakeServerClusterInterface cluster1(kEp1, kCluster1);
    FakeServerClusterInterface cluster2(kEp2, kCluster2);
    FakeServerClusterInterface cluster3(kEp2, kCluster3);

    // there should be nothing registered to start with.
    EXPECT_EQ(registry.Get({ kEp1, kCluster1 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp1, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp2, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp2, kCluster3 }), nullptr);
    EXPECT_EQ(registry.Get({ kInvalidEndpointId, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp1, kInvalidClusterId }), nullptr);

    // registration of invalid values is not acceptable
    {
        // registration has NULL interface
        // next is not null (meaning registration2 looks like already registered)
        ServerClusterRegistration registration1(cluster1);
        ServerClusterRegistration registration2(cluster2);
        registration2.next = &registration1;
        EXPECT_EQ(registry.Register(registration2), CHIP_ERROR_INVALID_ARGUMENT);

        // invalid path in cluster
        FakeServerClusterInterface invalidPathInterface(kInvalidEndpointId, kCluster1);
        ServerClusterRegistration registration3(invalidPathInterface);
        EXPECT_EQ(registry.Register(registration3), CHIP_ERROR_INVALID_ARGUMENT);

        // invalid path in cluster
        FakeServerClusterInterface invalidPathInterface2(kEp1, kInvalidClusterId);
        ServerClusterRegistration registration4(invalidPathInterface);
        EXPECT_EQ(registry.Register(registration4), CHIP_ERROR_INVALID_ARGUMENT);
    }

    ServerClusterRegistration registration1(cluster1);
    ServerClusterRegistration registration2(cluster2);
    ServerClusterRegistration registration3(cluster3);

    // should be able to register
    EXPECT_EQ(registry.Register(registration1), CHIP_NO_ERROR);
    EXPECT_EQ(registry.Register(registration2), CHIP_NO_ERROR);
    EXPECT_EQ(registry.Register(registration3), CHIP_NO_ERROR);

    // cannot register two implementations on the same path
    {
        FakeServerClusterInterface another1(kEp1, kCluster1);
        ServerClusterRegistration anotherRegisration1(another1);
        EXPECT_EQ(registry.Register(anotherRegisration1), CHIP_ERROR_DUPLICATE_KEY_ID);
    }

    // Items can be found back
    EXPECT_EQ(registry.Get({ kEp1, kCluster1 }), &cluster1);
    EXPECT_EQ(registry.Get({ kEp2, kCluster2 }), &cluster2);
    EXPECT_EQ(registry.Get({ kEp2, kCluster3 }), &cluster3);

    EXPECT_EQ(registry.Get({ kEp2, kCluster1 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp1, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp3, kCluster2 }), nullptr);

    // repeated calls work
    EXPECT_EQ(registry.Get({ kEp1, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp1, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp1, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp2, kCluster1 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp2, kCluster1 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp2, kCluster1 }), nullptr);

    // remove registrations
    EXPECT_EQ(registry.Unregister(&cluster2), CHIP_NO_ERROR);
    EXPECT_EQ(registry.Unregister(&cluster2), CHIP_ERROR_NOT_FOUND);

    // Re-adding works
    EXPECT_EQ(registry.Get({ kEp2, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Register(registration2), CHIP_NO_ERROR);
    EXPECT_EQ(registry.Get({ kEp2, kCluster2 }), &cluster2);

    // clean of an entire endpoint works
    EXPECT_EQ(registry.Get({ kEp2, kCluster3 }), &cluster3);
    registry.UnregisterAllFromEndpoint(kEp2);
    EXPECT_EQ(registry.Get({ kEp1, kCluster1 }), &cluster1);
    EXPECT_EQ(registry.Get({ kEp2, kCluster3 }), nullptr);

    registry.UnregisterAllFromEndpoint(kEp1);
    EXPECT_EQ(registry.Get({ kEp1, kCluster1 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp2, kCluster3 }), nullptr);
}

TEST_F(TestSingleEndpointServerClusterRegistry, StressTest)
{
    // make the test repeatable
    srand(1234);

    std::vector<FakeServerClusterInterface> items;
    std::vector<ServerClusterRegistration> registrations;

    static constexpr ClusterId kClusterTestCount   = 200;
    static constexpr EndpointId kEndpointTestCount = 10;
    static constexpr size_t kTestIterations        = 4;

    static_assert(kInvalidClusterId > kClusterTestCount, "Tests assume all clusters IDs [0...] are valid");
    static_assert(kTestIterations > 1, "Tests use different unregister methods. Need 2 or more passes.");

    items.reserve(kClusterTestCount);
    for (ClusterId i = 0; i < kClusterTestCount; i++)
    {
        auto endpointId = static_cast<EndpointId>(rand() % kEndpointTestCount);
        items.emplace_back(endpointId, i);
    }

    for (ClusterId i = 0; i < kClusterTestCount; i++)
    {
        registrations.emplace_back(items[i]);
    }

    SingleEndpointServerClusterRegistry registry;

    for (size_t test = 0; test < kTestIterations; test++)
    {
        for (ClusterId i = 0; i < kClusterTestCount; i++)
        {
            ASSERT_EQ(registry.Register(registrations[i]), CHIP_NO_ERROR);
        }

        // test that getters work
        for (ClusterId cluster = 0; cluster < kClusterTestCount; cluster++)
        {
            for (EndpointId ep = 0; ep < kEndpointTestCount; ep++)
            {
                if (items[cluster].GetPath().mEndpointId == ep)
                {
                    ASSERT_EQ(registry.Get({ ep, cluster }), &items[cluster]);
                }
                else
                {
                    ASSERT_EQ(registry.Get({ ep, cluster }), nullptr);
                }
            }
        }

        // clear endpoints. Stress test, unregister in different ways (bulk vs individual)
        if (test % 2 == 1)
        {
            // shuffle unregister
            std::vector<size_t> unregister_order;
            unregister_order.reserve(kClusterTestCount);
            for (size_t i = 0; i < kClusterTestCount; i++)
            {
                unregister_order.push_back(i);
            }

            std::default_random_engine eng(static_cast<std::default_random_engine::result_type>(rand()));
            std::shuffle(unregister_order.begin(), unregister_order.end(), eng);

            // unregister
            for (auto cluster : unregister_order)
            {
                // item MUST exist and be accessible
                ASSERT_EQ(registry.Get(items[cluster].GetPath()), &items[cluster]);
                ASSERT_EQ(registry.Unregister(&items[cluster]), CHIP_NO_ERROR);

                // once unregistered, it is not there anymore
                ASSERT_EQ(registry.Get(items[cluster].GetPath()), nullptr);
                ASSERT_EQ(registry.Unregister(&items[cluster]), CHIP_ERROR_NOT_FOUND);
            }

            // all endpoints should be clear
            for (ClusterId cluster = 0; cluster < kClusterTestCount; cluster++)
            {
                for (EndpointId ep = 0; ep < kEndpointTestCount; ep++)
                {
                    ASSERT_EQ(registry.Get({ ep, cluster }), nullptr);
                }
            }
        }
        else
        {
            // bulk unregister
            for (EndpointId ep = 0; ep < kEndpointTestCount; ep++)
            {
                registry.UnregisterAllFromEndpoint(ep);
            }
        }
    }
}

TEST_F(TestSingleEndpointServerClusterRegistry, ClustersOnEndpoint)
{
    std::vector<FakeServerClusterInterface> items;
    std::vector<ServerClusterRegistration> registrations;

    static constexpr ClusterId kClusterTestCount   = 200;
    static constexpr EndpointId kEndpointTestCount = 10;

    static_assert(kInvalidClusterId > kClusterTestCount, "Tests assume all clusters IDs [0...] are valid");

    items.reserve(kClusterTestCount);
    for (ClusterId i = 0; i < kClusterTestCount; i++)
    {
        items.emplace_back(static_cast<EndpointId>(i % kEndpointTestCount), i);
    }
    for (ClusterId i = 0; i < kClusterTestCount; i++)
    {
        registrations.emplace_back(items[i]);
    }

    SingleEndpointServerClusterRegistry registry;

    // place the clusters on the respecitve endpoints
    for (ClusterId i = 0; i < kClusterTestCount; i++)
    {
        ASSERT_EQ(registry.Register(registrations[i]), CHIP_NO_ERROR);
    }

    // this IS implementation defined: we always register at "HEAD" so the listing is in
    // INVERSE order of registering.
    for (EndpointId ep = 0; ep < kEndpointTestCount; ep++)
    {
        // Move to the end since we iterate in reverse order
        ClusterId expectedClusterId = ep + kEndpointTestCount * (kClusterTestCount / kEndpointTestCount);
        if (expectedClusterId >= kClusterTestCount)
        {
            expectedClusterId -= kEndpointTestCount;
        }

        // ensure that iteration happens exactly as we expect: reverse order and complete
        for (const auto & clusterId : registry.ClustersOnEndpoint(ep))
        {
            ASSERT_LT(expectedClusterId, kClusterTestCount);

            ServerClusterInterface * cluster = registry.Get({ ep, clusterId });
            ASSERT_NE(cluster, nullptr);
            ASSERT_TRUE(cluster->PathsContains(ConcreteClusterPath(ep, expectedClusterId)));
            expectedClusterId -= kEndpointTestCount; // next expected/registered cluster
        }

        // Iterated through all : we overflowed and got a large number
        ASSERT_GE(expectedClusterId, kClusterTestCount);
    }

    // invalid index works and iteration on empty lists is ok
    auto clusters = registry.ClustersOnEndpoint(kEndpointTestCount + 1);
    ASSERT_EQ(clusters.begin(), clusters.end());
}

TEST_F(TestSingleEndpointServerClusterRegistry, Context)
{
    FakeServerClusterInterface cluster1(kEp1, kCluster1);
    FakeServerClusterInterface cluster2(kEp1, kCluster2);
    FakeServerClusterInterface cluster3(kEp2, kCluster3);

    ServerClusterRegistration registration1(cluster1);
    ServerClusterRegistration registration2(cluster2);
    ServerClusterRegistration registration3(cluster3);

    {
        SingleEndpointServerClusterRegistry registry;
        EXPECT_FALSE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
        EXPECT_FALSE(cluster3.HasContext());

        // registry is NOT initialized
        EXPECT_EQ(registry.Register(registration1), CHIP_NO_ERROR);
        EXPECT_FALSE(cluster1.HasContext());

        // set up the registry
        TestServerClusterContext context;
        EXPECT_EQ(registry.SetContext(context.Create()), CHIP_NO_ERROR);

        EXPECT_TRUE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
        EXPECT_FALSE(cluster3.HasContext());

        // adding clusters automatically adds the context
        EXPECT_EQ(registry.Register(registration2), CHIP_NO_ERROR);
        EXPECT_TRUE(cluster2.HasContext());

        // clearing the context clears all clusters
        registry.ClearContext();
        EXPECT_FALSE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
        EXPECT_FALSE(cluster3.HasContext());

        EXPECT_EQ(registry.SetContext(context.Create()), CHIP_NO_ERROR);
        EXPECT_TRUE(cluster1.HasContext());
        EXPECT_TRUE(cluster2.HasContext());
        EXPECT_FALSE(cluster3.HasContext());

        EXPECT_EQ(registry.Register(registration3), CHIP_NO_ERROR);
        EXPECT_TRUE(cluster3.HasContext());

        // removing clears the context/shuts clusters down
        EXPECT_EQ(registry.Unregister(&cluster2), CHIP_NO_ERROR);
        EXPECT_TRUE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
        EXPECT_TRUE(cluster3.HasContext());

        // re-setting context works
        EXPECT_EQ(registry.SetContext(context.Create()), CHIP_NO_ERROR);
        EXPECT_TRUE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
        EXPECT_TRUE(cluster3.HasContext());

        // also not valid, but different
        TestServerClusterContext otherContext;

        EXPECT_EQ(registry.SetContext(otherContext.Create()), CHIP_NO_ERROR);
        EXPECT_TRUE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
        EXPECT_TRUE(cluster3.HasContext());

        // Removing an entire endpoint clears the context for clusters (shuts them down)
        registry.UnregisterAllFromEndpoint(kEp1);
        EXPECT_FALSE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
        EXPECT_TRUE(cluster3.HasContext());
    }

    // destructor clears the context
    EXPECT_FALSE(cluster1.HasContext());
    EXPECT_FALSE(cluster2.HasContext());
    EXPECT_FALSE(cluster3.HasContext());
}

TEST_F(TestSingleEndpointServerClusterRegistry, MultiPathRegistration)
{
    const std::array<ConcreteClusterPath, 4> kTestPaths{ {
        { 15, 100 },
        { 15, 88 },
        { 15, 20 },
        { 15, 33 },
    } };
    MultiPathCluster cluster(kTestPaths);
    ServerClusterRegistration registration(cluster);

    SingleEndpointServerClusterRegistry registry;
    ASSERT_EQ(registry.Register(registration), CHIP_NO_ERROR);

    for (auto & p : kTestPaths)
    {
        ASSERT_EQ(registry.Get(p), &cluster);
    }

    // some things not there...
    ASSERT_EQ(registry.Get({ 1, 20 }), nullptr);
    ASSERT_EQ(registry.Get({ 1, 200 }), nullptr);
    ASSERT_EQ(registry.Get({ 3, 200 }), nullptr);
    ASSERT_EQ(registry.Get({ 4, 33 }), nullptr);

    // Verify listing works: we should get the cluster once
    size_t cluster_count = 0;
    for (auto * c : registry.AllServerClusterInstances())
    {
        ASSERT_EQ(c, &cluster);
        cluster_count++;
    }
    ASSERT_EQ(cluster_count, 1u);

    // We can also iterate by endpoint and find all the paths.
    SingleEndpointServerClusterRegistry::ClustersList clusters = registry.ClustersOnEndpoint(15);
    auto it                                                    = clusters.begin();

    std::vector<ClusterId> returned_clusters;
    for (size_t i = 0; i < kTestPaths.size(); ++i)
    {
        ASSERT_NE(it, clusters.end());
        returned_clusters.push_back(*it);
        ++it;
    }
    ASSERT_EQ(it, clusters.end());

    std::sort(returned_clusters.begin(), returned_clusters.end());
    std::vector<ClusterId> expected_clusters;
    for (const auto & path : kTestPaths)
    {
        expected_clusters.push_back(path.mClusterId);
    }
    std::sort(expected_clusters.begin(), expected_clusters.end());
    ASSERT_EQ(returned_clusters, expected_clusters);

    ASSERT_EQ(registry.Unregister(&cluster), CHIP_NO_ERROR);
    for (auto & p : kTestPaths)
    {
        ASSERT_EQ(registry.Get(p), nullptr);
    }
}

TEST_F(TestSingleEndpointServerClusterRegistry, RejectDifferentEndpointPaths)
{
    {
        const std::array<ConcreteClusterPath, 2> kTestPaths{ {
            { 1, 100 },
            { 2, 88 },
        } };
        MultiPathCluster cluster(kTestPaths);
        ServerClusterRegistration registration(cluster);

        SingleEndpointServerClusterRegistry registry;
        ASSERT_EQ(registry.Register(registration), CHIP_ERROR_INVALID_ARGUMENT);
    }

    {
        const std::array<ConcreteClusterPath, 3> kTestPaths{ {
            { 1, 100 },
            { 1, 200 },
            { 3, 100 },
        } };
        MultiPathCluster cluster(kTestPaths);
        ServerClusterRegistration registration(cluster);

        SingleEndpointServerClusterRegistry registry;
        ASSERT_EQ(registry.Register(registration), CHIP_ERROR_INVALID_ARGUMENT);
    }
}

TEST_F(TestSingleEndpointServerClusterRegistry, StartupErrors)
{
    FakeServerClusterInterface cluster1(kEp1, kCluster1);
    CannotStartUpCluster cluster2(kEp2, kCluster2);

    ServerClusterRegistration registration1(cluster1);
    ServerClusterRegistration registration2(cluster2);

    {
        SingleEndpointServerClusterRegistry registry;
        EXPECT_FALSE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());

        // register without context works because startup not called yet
        EXPECT_EQ(registry.Register(registration1), CHIP_NO_ERROR);
        EXPECT_EQ(registry.Register(registration2), CHIP_NO_ERROR);

        EXPECT_FALSE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());

        TestServerClusterContext context;
        EXPECT_EQ(registry.SetContext(context.Create()), CHIP_ERROR_HAD_FAILURES);
        EXPECT_TRUE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());

        registry.ClearContext();
        EXPECT_FALSE(cluster1.HasContext());
        EXPECT_FALSE(cluster2.HasContext());
    }
}

TEST_F(TestSingleEndpointServerClusterRegistry, AllClustersIteration)
{
    FakeServerClusterInterface cluster1(kEp1, kCluster1);
    FakeServerClusterInterface cluster2(kEp2, kCluster2);
    FakeServerClusterInterface cluster3(kEp2, kCluster3);

    ServerClusterRegistration registration1(cluster1);
    ServerClusterRegistration registration2(cluster2);
    ServerClusterRegistration registration3(cluster3);

    SingleEndpointServerClusterRegistry registry;

    EXPECT_EQ(registry.Register(registration1), CHIP_NO_ERROR);
    EXPECT_EQ(registry.Register(registration2), CHIP_NO_ERROR);
    EXPECT_EQ(registry.Register(registration3), CHIP_NO_ERROR);

    std::vector<ServerClusterInterface *> found_clusters;
    for (auto * cluster : registry.AllServerClusterInstances())
    {
        found_clusters.push_back(cluster);
    }

    EXPECT_EQ(found_clusters.size(), 3u);
    EXPECT_NE(std::find(found_clusters.begin(), found_clusters.end(), &cluster1), found_clusters.end());
    EXPECT_NE(std::find(found_clusters.begin(), found_clusters.end(), &cluster2), found_clusters.end());
    EXPECT_NE(std::find(found_clusters.begin(), found_clusters.end(), &cluster3), found_clusters.end());

    registry.Unregister(&cluster2);

    found_clusters.clear();
    for (auto * cluster : registry.AllServerClusterInstances())
    {
        found_clusters.push_back(cluster);
    }

    EXPECT_EQ(found_clusters.size(), 2u);
    EXPECT_NE(std::find(found_clusters.begin(), found_clusters.end(), &cluster1), found_clusters.end());
    EXPECT_EQ(std::find(found_clusters.begin(), found_clusters.end(), &cluster2), found_clusters.end());
    EXPECT_NE(std::find(found_clusters.begin(), found_clusters.end(), &cluster3), found_clusters.end());
}

TEST_F(TestSingleEndpointServerClusterRegistry, UnregisterAllFromEndpointWithMultiPath)
{
    const std::array<ConcreteClusterPath, 2> kMultiPaths{ {
        { kEp1, kCluster2 },
        { kEp1, kCluster3 },
    } };

    FakeServerClusterInterface cluster1(kEp1, kCluster1);
    MultiPathCluster multiPathCluster(kMultiPaths);
    FakeServerClusterInterface otherEndpointCluster(kEp2, kCluster1);

    ServerClusterRegistration registration1(cluster1);
    ServerClusterRegistration multiPathRegistration(multiPathCluster);
    ServerClusterRegistration otherEndpointRegistration(otherEndpointCluster);

    SingleEndpointServerClusterRegistry registry;
    ASSERT_EQ(registry.Register(registration1), CHIP_NO_ERROR);
    ASSERT_EQ(registry.Register(multiPathRegistration), CHIP_NO_ERROR);
    ASSERT_EQ(registry.Register(otherEndpointRegistration), CHIP_NO_ERROR);

    // Cache one of the clusters on the endpoint we are about to clear.
    ASSERT_EQ(registry.Get({ kEp1, kCluster2 }), &multiPathCluster);

    registry.UnregisterAllFromEndpoint(kEp1);

    // All clusters on EP1 should be gone.
    EXPECT_EQ(registry.Get({ kEp1, kCluster1 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp1, kCluster2 }), nullptr);
    EXPECT_EQ(registry.Get({ kEp1, kCluster3 }), nullptr);

    // The cluster on EP2 should still be there.
    EXPECT_EQ(registry.Get({ kEp2, kCluster1 }), &otherEndpointCluster);
}
